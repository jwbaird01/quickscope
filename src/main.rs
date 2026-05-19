use tokio::process::Command;

/*
TODO: 
 - start with a sn1per scan
 - import to msfdb
 - if possible search and try to run msf modules
   + if success / gain session keep sessions and allow person to access
*/

/* 
    Needs to have workspace and file name from koboscan for ARGs input

    Possibly could use config input as well.. there seems to be more features than just default including nessus and other scanners
*/

async fn snipe(workspace:String, file:String) {
    // runs sn1per per host from input
}

#[tokio::main]
fn main() {
    println!("null")
}
