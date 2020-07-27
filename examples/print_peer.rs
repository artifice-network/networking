use networking::test_config;
fn main(){
    let (peer, config) = test_config();
    println!("{}", serde_json::to_string(&peer).unwrap());
}