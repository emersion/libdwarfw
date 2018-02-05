# libdwarfw

A C library to write DWARF debugging information.

It currently only supports [`.eh_frame`][eh_frame] with a few DWARF
instructions.

## Building

Install dependencies:

* meson
* libelf

Run these commands:

```
meson build
ninja -C build
```

## License

MIT

[eh_frame]: https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
