<<<<<<< HEAD
# BitTorrent Client in Go

This is a BitTorrent client implemented in Go. It can parse .torrent files, extract tracker and file information, compute info hashes, and interact with trackers to discover peers.

## Features
- Parse and decode bencoded data
- Extract tracker URL, file length, piece length, and piece hashes
- Compute info hash (SHA-1 of bencoded info dictionary)
- Make tracker requests and parse peer lists

## Usage

Build and run the program using Go:

```sh
./your_program.sh <command> <args>
```

### Commands
- `decode <bencoded-value>`: Decodes a bencoded value and prints it as JSON.
- `torrent-info <torrent-file>`: Prints tracker URL and file length from a torrent file.
- `info-hash <torrent-file>`: Prints the info hash of a torrent file.
- `info <torrent-file>`: Prints detailed torrent info, including piece hashes.
- `peers <torrent-file>`: Makes a tracker request and prints the raw response.

## License
MIT
=======
# Bittorrent-peer-to-peer-
>>>>>>> 569447c849be41379a20d9f1215732099bca659c
