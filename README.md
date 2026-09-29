# `porchpirate`

`cc -Os porchpirate.c -o porchpirate && sudo ./porchpirate | grep :443`

- no payload output - prints headers only
- packets with IPv6 extension headers labeled by protocol number only (not walked)
- IPv6 addresses not bracketed (addresses like `::1:443` ambiguous)
