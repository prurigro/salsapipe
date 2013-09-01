Overview:

    Exchanges Salsa20 keys encrypted with GPG between two peers connected through a socket.
    It then uses the exchanged Salsa20 keys to exchange encrypted messages, read in and out
    through supplied file descriptors.
    Contains a very simple example program 'salsamsg'.
    
Prerequisites:

    GPGME - Used to retrieve known public/private keys to exchange the salsa session keys securely...
        Available from: http://www.gnupg.org/related_software/gpgme/
    nettle - We use nettles salsa20 algorithm to encrypt and decrypt the actual message content once we've exchanged salsa20 keys.
        Available from: http://www.lysator.liu.se/~nisse/nettle/
    
Known Issues:

    Ubuntu Linux - The current nettle version in the ubuntu repositories is outdated and does not have a salsa20 cipher
    available. I recommend compiling the library yourself from the web address above. Version 2.7 or greater is recommended.
    
Compile:

    $ gcc -Wall -Wextra -O2 -o "salsamsg" "salsamsg.c" -lnettle -lgpgme
      
Usage:

    salsamsg -m <Mode> -i <IP> -p <Port> -l <Local PGP ID> -r <Remote PGP ID>
      Mode -
        If 'c' for Connect (Client)
        If 'l' for Listen (Server)
      IP -
        If Mode is 'c' then the remote IP to connect to
        If Mode is 'l' then the local IP to bind to
      Port -
        If Mode is 'c' then the remote Port to connect to
        If Mode is 'l' then the local Port to bind to
      Local PGP ID -
        The PGP ID for the Private Key to decrypt incoming Salsa keys (Your PGP ID)
      Remote PGP ID -
        The PGP ID for the Public Key to encrypt outing Salsa keys (Their PGP ID)

TODO:

    Automatic session key retransmission to avoid nonce re-use (which is bad! See: WEP)
