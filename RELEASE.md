# Release Notes

## new header implementation
this version features a new and imporved method of passing headers accross the network. instead of having headers be processed in the send/recv methods in async the headers are now processed in the aes_encrypt, and aes_decrypt functions.

## change in encryption
in this implementation headers are a known size of 125 bytes 50 for global peer hash 50 for peer hash (the pre-shared key between the peers) 16 for aes key, 8 for packet len and 1 for the badding. and in this way rsa is used to encrypt the header, that when decrypted provides an aes key randomly generated for each packet, that can be used to decrypt the rest of the data.

## change in examples
this version also has support for examples that use a much larger data transmission rate, that employs this encryption system. the examples have been re-factored so test rsa keys, and thus ArtificeConig and ArtificePeer can be saved in code rather then in an external file.