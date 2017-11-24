extern crate iron;
extern crate router;
extern crate bodyparser;
extern crate serde;
extern crate reqwest;
extern crate argon2;
extern crate base64;

extern crate pretty_env_logger;
#[macro_use] extern crate log;
#[macro_use] extern crate serde_qs as qs;
#[macro_use] extern crate serde_json;

use iron::{Iron, Request, Response, IronResult};
use iron::prelude::*;
use iron::status;
use router::{Router};

use reqwest::Client as Client;
use reqwest::header::{Headers, ContentType};
use reqwest::Url;

#[macro_use] extern crate serde_derive;
#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct Query {
    d: String,
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct QueryJSON {
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "Timestamp")]
    timestamp: i32,
}

fn construct_headers() -> Headers {
    let mut headers = Headers::new();
    headers.set(ContentType::json());
    headers
}

fn rquest_update_pw(dq: QueryJSON, pass: String) -> bool {
    let client = Client::new();
    let data = json!({
        "data": {
            "password": pass
        }
    });
    debug!("Post data: {:?}", data);

    let url = format!("http://httpbin.org/post?u={}", dq.username);
    match client.put(Url::parse(&url).unwrap())
              .headers(construct_headers())
              .json(&data)
              .send() {
                  Ok(res) => {
                      if res.status() == reqwest::StatusCode::Ok {
                          return true
                      } else {
                          return false
                      }
                  },
                  _ =>  false
              }
}

fn main() {
    pretty_env_logger::init().unwrap();
    let mut router = Router::new();

    router.get("/", default, "default");
    router.post("/password/reset", reset_pw, "/password/reset");

    fn default(_: &mut Request) -> IronResult<Response> {
        Ok(Response::with((status::Ok, "OK")))
    }

    fn reset_pw(req: &mut Request) -> IronResult<Response> {
        use base64::{decode};

        let json_body = req.get::<bodyparser::Json>();
        let mut pass: String = String::from("");

        let query_string_str = req.url.query().unwrap();
        let query_string: Query = qs::from_str(query_string_str).unwrap();

        let decoded = decode(&query_string.d).unwrap();
        let decoded_json: QueryJSON = serde_json::from_slice(&decoded).unwrap();
        debug!("{:?}", decoded_json);

        match json_body {
            Ok(Some(json_body)) => {
                debug!("post by web page: {:?}", json_body);
                let pass_str = json_body.as_object().unwrap().get("pass").unwrap().as_str().unwrap();
                pass = String::from(pass_str);
            },
            Ok(None) => error!("No body"),
            Err(err) => error!("Error: {:?}", err)
        };
        debug!("{:?}", rquest_update_pw(decoded_json, pass.clone()));
        Ok(Response::with((status::Ok, "ok")))
    }

    let _server = Iron::new(router).http("0.0.0.0:3307").unwrap();
    info!("On 3307");
}
