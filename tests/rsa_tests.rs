use networking::test_config;
#[test]
fn use_strings() {
    let (peer, config) = test_config();
    let key = config.host_data().privkeycomp();
    println!("{}", key.n().to_string_unstable());
}
#[test]
fn optimized_mod_exp() {
    let (_, config) = test_config();
    let key = config.host_data().privkeycomp();
}
