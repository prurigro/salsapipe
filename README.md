Overview:

    Exchanges Salsa20 keys encrypted through GPG between two peers connected through a socket.
    It then uses the exchanged Salsa20 keys to exchange encrypted messages, read in and out
    through supplied file descriptors.

Compile:

    $ gcc -Wall -Wextra -O2 -o "salsamsg" "salsamsg.c" -lnettle -lgpgme
      
Usage:

    salsamsg -m <Mode> -i <IP> -p <Port> -l <Local PGP ID> -r <Remote PGP ID>
      Mode -  'c' for Connect (Client)
              'l' for Listen (Server)
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
