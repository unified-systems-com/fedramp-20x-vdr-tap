# fedramp-20x-vdr-tap

A TAP plugin (`fedramp_20x_vdr`) that evaluates each vulnerability finding under FedRAMP 20x Vulnerability Detection and Response, seeds FedRAMP's timeframe tables as data, and computes the deadlines they imply. It starts from the worst case for every factor and lowers a factor only when evidence is attached.

Status: specification in review. See [`specs/spec-fedramp-20x-vdr-v0.md`](specs/spec-fedramp-20x-vdr-v0.md).

Licensed under Apache-2.0.
