INPUT = ['ICE ICE BABY\x04\x04\x04\x04', 'ICE ICE BABY\x05\x05\x05\x05', 'ICE ICE BABY\x01\x02\x03\x04']
OUTPUT = ['ICE ICE BABY', None, None]

class PaddingException(Exception):
    pass

def unpad(input_):
    input_ = input_.encode()
    if len(input_) % 16 != 0:
        raise PaddingException
    last = input_[-1]
    if 1 <= last <= 16:
        if len(input_) >= last and input_[-last:] == bytes([last] * last):
            return input_[:-last].decode()
    raise PaddingException

def main():
    for input_, output in zip(INPUT, OUTPUT):
        try:
            text = unpad(input_)
            assert text == output
        except PaddingException:
            assert output is None

if __name__ == '__main__':
    main()
