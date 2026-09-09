//! Lab probe: sends a Quickshell/Unlock authorization for a local user over
//! the agent socket and prints the raw decision. Usage:
//! cargo run -p oma-id-agent-ipc --example probe -- /path/to.sock <user>
use oma_id_agent_ipc::{
    AgentRequest, AuthorizationRequest, Consumer, Operation, PROTOCOL_VERSION,
};
use std::os::unix::net::UnixStream;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let socket = args.get(1).expect("socket path");
    let user = args.get(2).cloned().unwrap_or_else(|| "root".into());
    let mut stream = UnixStream::connect(socket).expect("connect");
    let request = AuthorizationRequest {
        version: PROTOCOL_VERSION,
        request_id: [7; 16],
        local_username: user,
        consumer: Consumer::Quickshell,
        operation: Operation::Unlock,
    };
    oma_id_agent_ipc::write_message(&mut &stream, &AgentRequest::Authorization(request))
        .expect("write");
    let response: oma_id_agent_ipc::AgentResponse =
        oma_id_agent_ipc::read_message(&mut &stream).expect("read");
    println!("decision: {:?}", response.decision);
}
