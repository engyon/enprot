use cpu_time::ThreadTime;
use std::fs;

use Fixture;

#[test]
fn pbkdf_cache() {
    let ept = Fixture::blank("in.ept");
    fs::write(
        &ept.path.to_str().unwrap(),
        "
// <( BEGIN Agent_007 )>
Secret 1
// <( END Agent_007 )>
// <( BEGIN Agent_007 )>
Secret 2
// <( END Agent_007 )>
// <( BEGIN Agent_007 )>
Secret 3
// <( END Agent_007 )>
// <( BEGIN Agent_007 )>
Secret 4
// <( END Agent_007 )>
",
    )
    .unwrap();
    let out = Fixture::blank("out.ept");
    const MSEC: &str = "20";
    const SAMPLE_COUNT: u32 = 3;
    let (encms_cache, encms_nocache, decms_cache, decms_nocache): (u32, u32, u32, u32);
    let mut elapsed_ms: u32 = 0;

    // with pbkdf cache
    for _ in 0..SAMPLE_COUNT {
        let now = ThreadTime::now();
        enprot::app_main(vec![
            "enprot",
            "-e",
            "Agent_007",
            "--pbkdf",
            "pbkdf2-sha256",
            "--pbkdf-msec",
            MSEC,
            "-k",
            "Agent_007=password",
            &ept.path.to_str().unwrap(),
            "-o",
            &out.path.to_str().unwrap(),
        ]);
        elapsed_ms += now.elapsed().as_millis() as u32;
    }
    encms_cache = (elapsed_ms as f32 / SAMPLE_COUNT as f32) as u32;
    // check output
    assert!(&fs::read_to_string(&out.path)
        .unwrap()
        .contains("$pbkdf2-sha256$"));
    assert_ne!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&out.path).unwrap(),
    );
    elapsed_ms = 0;
    for _ in 0..SAMPLE_COUNT {
        let dec = Fixture::blank("dec.ept");
        let now = ThreadTime::now();
        enprot::app_main(vec![
            "enprot",
            "-d",
            "Agent_007",
            "-k",
            "Agent_007=password",
            &out.path.to_str().unwrap(),
            "-o",
            &dec.path.to_str().unwrap(),
        ]);
        elapsed_ms += now.elapsed().as_millis() as u32;
        assert_eq!(
            &fs::read_to_string(&ept.path).unwrap(),
            &fs::read_to_string(&dec.path).unwrap()
        );
    }
    decms_cache = (elapsed_ms as f32 / SAMPLE_COUNT as f32) as u32;

    // without pbkdf cache
    elapsed_ms = 0;
    for _ in 0..SAMPLE_COUNT {
        let now = ThreadTime::now();
        enprot::app_main(vec![
            "enprot",
            "-e",
            "Agent_007",
            "--pbkdf",
            "pbkdf2-sha256",
            "--pbkdf-msec",
            MSEC,
            "--pbkdf-disable-cache",
            "-k",
            "Agent_007=password",
            &ept.path.to_str().unwrap(),
            "-o",
            &out.path.to_str().unwrap(),
        ]);
        elapsed_ms += now.elapsed().as_millis() as u32;
    }
    encms_nocache = (elapsed_ms as f32 / SAMPLE_COUNT as f32) as u32;
    // check output
    assert!(&fs::read_to_string(&out.path)
        .unwrap()
        .contains("$pbkdf2-sha256$"));
    assert_ne!(
        &fs::read_to_string(&ept.path).unwrap(),
        &fs::read_to_string(&out.path).unwrap(),
    );
    elapsed_ms = 0;
    for _ in 0..SAMPLE_COUNT {
        let dec = Fixture::blank("dec.ept");
        let now = ThreadTime::now();
        enprot::app_main(vec![
            "enprot",
            "-d",
            "Agent_007",
            "-k",
            "Agent_007=password",
            "--pbkdf-disable-cache",
            &out.path.to_str().unwrap(),
            "-o",
            &dec.path.to_str().unwrap(),
        ]);
        elapsed_ms += now.elapsed().as_millis() as u32;
        assert_eq!(
            &fs::read_to_string(&ept.path).unwrap(),
            &fs::read_to_string(&dec.path).unwrap()
        );
    }
    decms_nocache = (elapsed_ms as f32 / SAMPLE_COUNT as f32) as u32;

    // using cache should be consistently quicker
    assert!(encms_cache < encms_nocache);
    assert!(decms_cache < decms_nocache);
}
