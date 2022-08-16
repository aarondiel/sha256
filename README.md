<h1 align="center">SHA256</h1>

<img align="center" src="https://user-images.githubusercontent.com/38919146/184832574-da600004-a281-456b-b40d-9b1fd30dad51.svg"/>

a simple implementation of the sha256 hashing algorithm

## compile & run

to complie simply run `make`

then the binary can be executed with any string of your liking:
```sh
> ./sha256 "hello world"
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

---

## TODO
- convert to use little endianess to avoid conversions
- input through piping
- write detailed explanation
