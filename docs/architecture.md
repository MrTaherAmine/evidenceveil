# Architecture

EvidenceVeil is a local-only modular Python CLI. The core pipeline is: discovery → format detection → semantic classification → policy resolution → transformation → utility/risk validation → bundle packaging → offline reporting. Original evidence is opened read-only and outputs are created in a separate staging directory before an atomic directory rename.
