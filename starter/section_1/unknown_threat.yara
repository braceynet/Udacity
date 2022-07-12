rule unknown_threat {
  meta:
    Author = "@jbracey"
    Description = "this rule detects the presence of unknown threat scripts not identified by virus scanner"
strings:
    $SSH_T = "SSH-T"
    $SSH_One = "SSH-One"
    $darkl0rd = "darkl0rd.com"
condition:
     any of them
}
