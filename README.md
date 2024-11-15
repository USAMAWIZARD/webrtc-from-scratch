** still under development 
# TODO List

- [ ] Signal passing for callbacks
- [ ] make it browser compatible
- [ ] add basic security checks
- [ ] refactor encryption and decryption logic
- [ ] DTLS decryption
- [ ] Implement state changes for ICE, DTLS, and WebRTC
- [ ] refactor implementation
- [ ] Complete DTLS finish message verification
- [ ] Threading


** 
This project tries to implement a very minamal webrtc implementation without considering much about to learn and understand in depth how WebRTC works  <br>

It will make a WebRTC connection from another peer and send a stream in the simplest way possible <br>

https://github.com/user-attachments/assets/f8e3003f-2fb2-470a-aa16-a6fb0e0c798b


# WebRTC Streaming from Scrach implementtion to Gstreamer Client 
sending a basic video from webrtc scrach implementation to a Gstreamer WebRTC Client.

## Build the Program

1. git clone https://github.com/USAMAWIZARD/webrtc-from-scrach.git
2. Run the following command to build the program:

Build Scrach WebRTC implementation <br>
``` 
make
 ```

Build Gstreamer Client WebRTC <br>

```
cd GstreamerClient
make 
```


## Start Signalling Server

```
cd SignallingServer/
npm i 
npm start 
```


## Start Scrach implementation (sender)


```sh
./webrtc
```

## Start Gstreamer Client (receiver)

Once the receiver is started, run your program with the following command:

```sh
cd ./GstreamerClient
./webrtc_recv
```

now WebRTC Scrach implementation Will send a video to Gstreamer Client.


