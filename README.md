# grsott

A version of [grott](https://github.com/johanmeijer/grott)'s proxy for Growatt inverter traffic.

A specific subset of packets are decoded, and sent to an MQTT broker; so you could show them in Home Assistant.

`.` and `src/` is the rust application which acts as the proxy, and some support tooling.
`poll/` contains a python script to capture official answers from the real API.
`view/` contains a UI for exploring the packets, via. `cargo run --bin serve`
