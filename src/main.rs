use std::env;
mod funky;

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
fn help(full:bool){
    if full {
        println!("FULLHELP");
    }
    println!("quickscope -w <NAME_WORKSPACE> -f <FROM_KOBOSCAN>")
}

/*
I need to import the IP processing from koboscan, this honestly may replace it.. 
I need to look into if there is a mode that skips port scan then runs the other modules
 - doing so will speed up the actual scanning but still pull the extra info and categorize it into sn1per and msfdb formats
*/

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--help".to_string()) || args.contains(&"-h".to_string()) {
        help(true);
    } else if args.contains(&"-w".to_string()) && args.contains(&"-f".to_string()) {
        funky::snipe("test_space".to_string(),"1.1.1.1,8.8.8.8".to_string()).await;
    }
}
