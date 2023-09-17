mod crc32;

use malwaredb_lzjd::{LZDict, LZJDError};

use std::fs::File;
use std::io::Write;
use std::io::{self, BufRead, BufReader, BufWriter, Read};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::rc::Rc;

use clap::Parser;
use murmurhash3::Murmur3HashState;
use rayon::prelude::*;
use walkdir::WalkDir;

#[derive(Debug)]
enum Error {
    Io(String),
    Walkdir(String),
    ThreadPoolBuild(String),
    Lzjd(LZJDError),
}

#[derive(Parser, Debug)]
struct Args {
    /// Generate SDBFs from directories and files
    #[arg(short = 'd')]
    deep: bool,

    /// Compare SDBFs in file, or two SDBF files
    #[arg(short = 'c')]
    compare: bool,

    /// Compare all pairs in source data
    #[arg(short = 'g')]
    gen_compare: bool,

    /// Only show results >= threshold
    #[arg(short = 't', default_value = "1")]
    threshold: u32,

    /// Restrict compute threads to N threads
    #[arg(short = 'p', default_value_t = num_cpus::get())]
    threads: usize,

    /// Send output to files
    #[arg(short = 'o', value_name = "FILE")]
    files: Option<String>,

    /// Sets the input file to use
    #[arg(long = "input")]
    input: Vec<String>,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err.to_string())
    }
}

impl From<walkdir::Error> for Error {
    fn from(err: walkdir::Error) -> Self {
        Error::Walkdir(err.to_string())
    }
}

impl From<rayon::ThreadPoolBuildError> for Error {
    fn from(err: rayon::ThreadPoolBuildError) -> Self {
        Error::ThreadPoolBuild(err.to_string())
    }
}

impl From<LZJDError> for Error {
    fn from(err: LZJDError) -> Self {
        Error::Lzjd(err)
    }
}

type Result<T> = std::result::Result<T, Error>;

fn main() {
    let args = Args::parse();

    if args.input.is_empty() {
        eprintln!(
            "No input files specified. Run with `--input` or with `--help` for more information."
        );
        process::exit(-1);
    }

    if let Err(e) = run(args) {
        eprintln!("{:?}", e);
        process::exit(-1);
    }
}

fn run(args: Args) -> Result<()> {
    let deep = args.deep;
    let to_compare = args.compare;
    let gen_compare = args.gen_compare;
    let threshold = args.threshold;
    let num_threads = args.threads;

    let input_paths: Vec<PathBuf> = if deep {
        args.input
            .iter()
            .map(PathBuf::from)
            .flat_map(WalkDir::new)
            .try_fold(
                vec![],
                |mut v: Vec<PathBuf>, r: walkdir::Result<walkdir::DirEntry>| match r {
                    Ok(entry) => {
                        let path = entry.path();
                        if path.is_file() {
                            v.push(path.to_owned());
                        }
                        Ok(v)
                    }
                    Err(e) => Err(e),
                },
            )?
    } else {
        args.input.iter().map(PathBuf::from).collect()
    };

    let output_path = args.files.map(PathBuf::from);

    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build_global()?;

    let mut writer = create_out_writer(&output_path)?;

    if to_compare {
        if input_paths.is_empty() || input_paths.len() > 2 {
            return Err(LZJDError::from("Can only compare at most two indexes at a time!").into());
        }

        let hashes_a: Rc<Vec<(LZDict, String)>> = Rc::from(read_hashes_from_file(&input_paths[0])?);

        let hashes_b = if input_paths.len() == 2 {
            Rc::from(read_hashes_from_file(&input_paths[1])?)
        } else {
            Rc::clone(&hashes_a)
        };

        compare(&hashes_a, &hashes_b, threshold, &mut writer)?;
    } else if gen_compare {
        gen_comp(&input_paths, threshold, &mut writer)?;
    } else {
        hash_files(&input_paths, Some(&mut writer))?;
    }

    Ok(())
}

fn read_hashes_from_file(path: &Path) -> Result<Vec<(LZDict, String)>> {
    let file_handle = File::open(path)?;

    BufReader::new(file_handle)
        .lines()
        .try_fold(vec![], |mut v, line| {
            let line = line?;
            let line = line.trim();
            if !line.is_empty() {
                match line.rfind(':') {
                    Some(colon_index) if colon_index > 5 => {
                        let file_name = &line[5..colon_index];
                        let b64 = &line[colon_index + 1..];
                        let dict = LZDict::from_base64_string(b64)?;
                        v.push((dict, file_name.to_owned()));
                    }
                    _ => return Err(LZJDError::from("Could not parse line").into()),
                }
            }
            Ok(v)
        })
}

/// Perform comparisons of the given digests lists. If each list points to
/// the same object, only the above-diagonal elements of the comparison
/// matrix will be performed
fn compare(
    dicts_a: &[(LZDict, String)],
    dicts_b: &[(LZDict, String)],
    threshold: u32,
    writer: &mut dyn Write,
) -> Result<()> {
    let same = std::ptr::eq(dicts_a, dicts_b);
    let similarities: Vec<(String, String, u32)> = dicts_a
        .par_iter()
        .enumerate()
        .fold(Vec::new, |mut v, (i, (dict_a, name_a))| {
            let j_start = if same { i + 1 } else { 0 };
            dicts_b.iter().skip(j_start).for_each(|(dict_b, name_b)| {
                let similarity = (dict_a.similarity(dict_b) * 100.).round() as u32;
                if similarity >= threshold {
                    v.push((name_a.to_owned(), name_b.to_owned(), similarity));
                }
            });
            v
        })
        .reduce(Vec::new, |mut v, mut r| {
            v.append(&mut r);
            v
        });

    similarities
        .iter()
        .try_for_each(|(name_a, name_b, similarity)| {
            writer.write_fmt(format_args!("{}|{}|{:03}\n", name_a, name_b, similarity))
        })?;

    Ok(())
}

/// Generate the set of digests and do the all pairs comparison at the same time.
fn gen_comp(paths: &[PathBuf], threshold: u32, writer: &mut dyn Write) -> Result<()> {
    let dicts: Rc<Vec<(LZDict, String)>> = Rc::from(hash_files(paths, None)?);

    compare(&dicts, &dicts, threshold, writer)
}

/// Digest and print out the hashes for the given list of files
fn hash_files(paths: &[PathBuf], writer: Option<&mut dyn Write>) -> Result<Vec<(LZDict, String)>> {
    let build_hasher = Murmur3HashState::default();

    let dicts: Result<Vec<(LZDict, String)>> = paths
        .par_iter()
        .try_fold(Vec::new, |mut v, r| {
            let file = File::open(r)?;

            let path_name = r.to_str().unwrap();

            let bytes = BufReader::new(file)
                .bytes()
                .map(std::result::Result::unwrap);

            v.push((
                LZDict::from_bytes_stream(bytes, &build_hasher),
                path_name.to_owned(),
            ));

            Ok(v)
        })
        .try_reduce(Vec::new, |mut v, mut results| {
            v.append(&mut results);
            Ok(v)
        });
    let dicts = dicts?;
    if let Some(writer) = writer {
        dicts
            .iter()
            .try_for_each(|d| writer.write_fmt(format_args!("lzjd:{}:{}\n", d.1, d.0)))?;
    }
    Ok(dicts)
}

fn create_out_writer(out_path: &Option<PathBuf>) -> Result<Box<dyn Write>> {
    if let Some(path) = out_path {
        Ok(Box::from(BufWriter::new(File::create(path)?)))
    } else {
        Ok(Box::from(BufWriter::new(io::stdout())))
    }
}
