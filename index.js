const pcap = require('pcap')
const dns = require('dns').promises
const pcap_session = pcap.createSession('en0', "ip proto \\tcp");
const app = require('express')();
const http = require('http').createServer(app);
const io = require('socket.io')(http);

app.get('/', function (req, res) {
  res.sendFile(__dirname + '/index.html');
});

http.listen(3000, function () {
  io.on('connection', function (socket) {
    pcap_session.on('packet', function (raw_packet) {
      try {
        const packet = pcap.decode.packet(raw_packet);
        const saddr = packet.payload.payload.saddr.toString()
        const daddr = packet.payload.payload.daddr.toString()
        const sport = packet.payload.payload.payload.sport.toString()
        const dport = packet.payload.payload.payload.dport.toString()

        if (saddr.indexOf("192.168") < 0) {
          dns.lookupService(saddr, sport)
            .then(({hostname}) => {
              socket.emit('packet', hostname + ":" + sport)
            })
            .catch(error => {
              socket.emit('packet', saddr + ":" + sport)
            })
        }

        if (daddr.indexOf("192.168") < 0) {
          dns.lookupService(daddr, dport)
            .then(({hostname}) => {
              socket.emit('packet', hostname + ":" + dport)
            })
            .catch(error => {
              socket.emit('packet', daddr + ":" + dport)
            })
        }
      } catch (e) {
        console.log(e)
      }
    })
  })
})




