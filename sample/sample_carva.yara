rule flash_swf 
{
  meta:
    desc = "SWF file"
    ext = "swf"
    ruby = "hdr = file.read(8); magic, ver, len = hdr.unpack('A3CV') ; (hdr << file.read(len-8)) if ver <= 11"
  strings: 
    $uncompressed = "FWS"
    $compressed   = "CWS"
  condition: $uncompressed or $compressed
}

rule x509_public_key_infrastructure_cert
{
  meta:
    desc = "X.509 PKI Certificate"
    ext = "crt"
    ruby = "hdr = file.read(4); magic, len = hdr.unpack('nn') ; hdr << file.read(len-4)"

  strings: $a = {30 82 ?? ?? 30 82 ?? ??}
  condition: $a
}

rule pkcs8_private_key_information_syntax_standard
{
  meta:
    desc = "PKCS #8: Private-Key"
    ext = "key"
    ruby = "hdr = file.read(4); magic, len = hdr.unpack('nn') ; hdr << file.read(len-4)"

  strings: $a = {30 82 ?? ?? 02 01 00}
  condition: $a
}




