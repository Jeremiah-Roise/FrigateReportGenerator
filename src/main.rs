use minijinja::{ Environment, context, syntax::SyntaxConfig, };
use ollama_rs::generation::completion::request::GenerationRequest;
use ollama_rs::generation::completion::GenerationResponse;
use ollama_rs::models::ModelOptions;
use reqwest::blocking as reqwest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::futures;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::path::Path;
use std::thread::current;
use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{Datelike, Local};
use ollama_rs::Ollama;
use tokio::runtime::Handle;
use tokio::task;

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Event {
    id: String,
    label: Option<String>,
    sub_label: Option<String>,
    camera: String,
    start_time: Option<f64>,
    end_time: Option<f64>,
    false_positive: Option<bool>,
    zones: Option<Vec<String>>,
    thumbnail: Option<String>,
    has_clip: Option<bool>,
    has_snapshot: Option<bool>,
    retain_indefinitely: Option<bool>,
    plus_id: Option<String>,
    model_hash: Option<String>,
    detector_type: Option<String>,
    model_type: Option<String>,
    data: Value, // Use Value for arbitrary JSON object
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct InferredData {
    threat_level: f32,
    suspiciousness: f32,
    interest: f32,
    description: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct CombinedEventData {
    event: Event,
    inferreddata: InferredData,
}

impl Event {
    fn extract_inferred_data(self) -> Option<CombinedEventData> {
        let data = &self.data;
        if let Value::Object(val) = data {
            if let Option::Some(description) = val.get("description") {
                let description = description.as_str().expect("Description is not a string.");
                let data: Result<InferredData, _> =
                    serde_json::from_str(&description.replace("```json", "").replace("```", ""));
                match data {
                    Err(errortext) => {
                        println!("\n\n{:#?}", errortext);
                        println!("{:#?}\n\n", description);
                        None
                    }
                    Ok(data) => Some(CombinedEventData {
                        event: self,
                        inferreddata: data,
                    }),
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

fn main() {
    // let _ = delete_file("EventDescriptions.txt");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let aftertimestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("expect time to go forward")
        .as_secs()
        - (24 * 60 * 60);
    let body = client
        .get(format!(
            "https://cam.home.com/api/events?after={}&limit=1000",
            aftertimestamp
        ))
        .send()
        .unwrap();
    println!("response {:#?}", &body);
    println!("Timestamp {aftertimestamp:#?}");

    let json_data: Vec<Event> = body.json::<Vec<Event>>().unwrap();

    let mut listofdata: Vec<CombinedEventData> = vec![];
    for i in json_data {
        if let Some(data) = i.extract_inferred_data() {
            listofdata.push(data);
        }
    }
    generate_latex(listofdata).unwrap();
}

// Appends a string to a file.  Returns an io::Result<(), io::Error> to indicate success or failure.
fn append_to_file(filepath: &str, content: &str) -> io::Result<()> {
    let path = Path::new(filepath);
    let mut file = File::options()
        .append(true)
        .create(true) // Create if it doesn't exist
        .open(path)?;

    writeln!(file, "{}", content)?; // Write the content with a newline
    Ok(())
}

fn generate_latex(events: Vec<CombinedEventData>) -> io::Result<()> {
    let mut env = Environment::new();
    env.set_syntax(
        SyntaxConfig::builder()
            .block_delimiters("\\BLOCK{", "}")
            .variable_delimiters("\\VAR{", "}")
            .comment_delimiters("\\#{", "}")
            .build()
            .unwrap(),
    );
    env.add_template("report", include_str!("./report_template.tex"))
        .unwrap();
    let tmpl = env.get_template("report").unwrap();

    let mut total_interest = 0.0;
    let mut total_suspiciousness = 0.0;
    let mut total_threat = 0.0;
    for event in &events {
        total_interest += event.inferreddata.interest as f32;
        total_threat += event.inferreddata.threat_level as f32;
        total_suspiciousness += event.inferreddata.suspiciousness as f32;
    }
    let number_of_events = events.len() as f32;
    let average_interest = total_interest / number_of_events;
    let average_suspiciousness = total_suspiciousness / number_of_events;
    let average_threat = total_threat / number_of_events;


    let critical_events: Vec<CombinedEventData> = events.clone().into_iter().filter(
        |event| event.inferreddata.threat_level > (average_threat * 2.0) ||
        event.inferreddata.suspiciousness > (average_suspiciousness * 2.0) ||
        event.inferreddata.interest > (average_interest * 2.0)).collect();

    let ollama = Ollama::default();
    let mut todays_history = String::new();
    for event in events {
        todays_history += &event.inferreddata.description;
    }

    let futureval = async {
        let request = GenerationRequest::new("deepseek-r1:32b".to_string(), format!("Summarize the data contained in these events gathered from a security camera system. {}", todays_history).to_string());
        ollama.generate(request).await
    };
    let rt  = tokio::runtime::Runtime::new().unwrap();
    let val: GenerationResponse = rt.block_on(futureval).unwrap();
    let summary = val.response.split("</think>").last();
    
    //println!("{:#?}", val);

    let timenow = Local::now();
    let mut file = File::options()
        .append(true)
        .create(true) // Create if it doesn't exist
        .open("latex_report_test.tex")?;
    let context = context!(
        year => timenow.year(),
        month => timenow.month(),
        day => timenow.day(),
        average_interest => average_interest,
        average_suspiciousness => average_suspiciousness,
        average_threat => average_threat,
        summary => summary,
        events => critical_events
        );

    writeln!( file, "{}", tmpl.render(context).unwrap())?; // Write the content with a newline
    Ok(())
}

// Deletes a file. Returns an io::Result<(), io::Error> to indicate success or failure.
fn delete_file(filepath: &str) -> io::Result<()> {
    let path = Path::new(filepath);
    std::fs::remove_file(path)?;
    Ok(())
}
