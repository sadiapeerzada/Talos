"""RFC 8032 §7.1 test 1: public verification vector, never an authority/approval."""
from talos.pilot.authority import verify_signature


def main():
    public=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
    signature=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
    verify_signature(public,signature,b'')
    try:verify_signature(public,signature,b'wrong message')
    except Exception:pass
    else:raise AssertionError('invalid message accepted')
    print('RFC8032 public-vector verification passed; no authority or approval created')


if __name__=='__main__':main()
