# PassSigner

**Passbook signing utility for PHP**

PassSigner is both a library and a CLI tool to sign and verify Apple's Passbook package files (`*.pkpass`).

With PassSigner you can:

 - Sign and zip a raw pass directory
 - Unzip and verify a signed pass


## Sign and Zip a Raw Pass Directory

    $ /path/to/signpass -p /my/pass/directory -c /path/to/MyCert.pem -w <CertificatePassword> -o /dest/PassFile.pkpass

**Important**: in order to generate and sign a pass you need to **obtain a valid pass certificate from Apple**. Certificates are issued to registered iOS developers (any paid plan).

## Unzip and Verify a Signed Pass

    $ /path/to/signpass -v /path/to/PassFile.pkpass

## Resources

For Passbook's **official specifications** visit Apple's [Passbook Developers page](https://developer.apple.com/passbook/).

For a more detailed example you may want to read [Digital Tickets with PHP and Apple Passbook](http://www.sitepoint.com/create-digital-tickets-with-php-and-apple-passbook/) on Sitepoint.

## License

PassSigner is licensed under the MIT License - see the `LICENSE` file for details.