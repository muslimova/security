class Cipher:
    def __init__(self):
        raise NotImplementedError("Must use a subclass of generic `Cipher`")

    def encrypt_text(self, text):
        return self.encrypt(text.encode()).decode()

    def decrypt_text(self, text):
        return self.decrypt(text.encode()).decode()

    def encrypt(self, data):
        raise NotImplementedError("Must use a subclass of generic `Cipher`")

    def decrypt(self, data):
        raise NotImplementedError("Must use a subclass of generic `Cipher`")

    # сдвиг влево
    def _leftshift(self, val, r_bits, max_bits):
        v1 = (val << r_bits % max_bits) & (2 ** max_bits - 1)
        v2 = (val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits))
        return v1 | v2

    # сдвиг вправо
    def _rightshift(self, val, r_bits, max_bits):
        v1 = (val & (2 ** max_bits - 1)) >> r_bits % max_bits
        v2 = val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1)
        return v1 | v2

    def _expand_key(self, key, word_size, rounds):
        # выравнивание ключа
        def _align_key(key, align_val):
            while len(key) % (align_val):
                key += (b"\x00")
            L = []
            for i in range(0, len(key), align_val):
                L.append(int.from_bytes(key[i: i + align_val], byteorder="little"))
            return L

        # необходимые константы
        def _const(w):
            if w == 16:
                return (0xB7E2, 0x9E38)
            elif w == 32:
                return (0xB7E15164, 0x9E3779B8)
            elif w == 64:
                return (0xB7E151628AED2A6A, 0x9E3779B97F4A7C14)
            raise ValueError("Bad word sie")

        # заполняем массив S, где S[0] = Pw, S[i+1] = S[i]+Qw
        def _extend_key(w, r):
            P, Q = _const(w)
            S = [P]
            t = 2 * (r + 1)
            for i in range(1, t):
                S.append((S[i - 1] + Q) % 2 ** w)
            return S

        # перемешиваем элементы массивов L и S
        def _mix(L, S, r, w, c):
            t = 2 * (r + 1)
            m = max(c, t)
            A = B = i = j = 0
            for k in range(3 * m):
                A = S[i] = self._leftshift(S[i] + A + B, 3, w)
                B = L[j] = self._leftshift(L[j] + A + B, A + B, w)
                i = (i + 1) % t
                j = (j + 1) % c
            return S

        aligned = _align_key(key, word_size // 8)
        extended = _extend_key(word_size, rounds)
        S = _mix(aligned, extended, rounds, word_size, len(aligned))
        return S

    # шифрование
    def _encrypt_block(self, data, expanded_key, block_size, rounds):
        w = block_size // 2
        b = block_size // 8
        mod = 2 ** w

        A = int.from_bytes(data[: b // 2], byteorder="little")
        B = int.from_bytes(data[b // 2:], byteorder="little")

        A = (A + expanded_key[0]) % mod
        B = (B + expanded_key[1]) % mod
        for i in range(1, rounds + 1):
            A = (self._leftshift((A ^ B), B, w) + expanded_key[2 * i]) % mod
            B = (self._leftshift((A ^ B), A, w) + expanded_key[2 * i + 1]) % mod
        res = A.to_bytes(b // 2, byteorder="little") + B.to_bytes(b // 2, byteorder="little")
        return res

    # дешифрование
    def _decrypt_block(self,data, expanded_key, block_size, rounds):
        w = block_size // 2
        b = block_size // 8
        mod = 2 ** w

        A = int.from_bytes(data[: b // 2], byteorder="little")
        B = int.from_bytes(data[b // 2:], byteorder="little")

        for i in range(rounds, 0, -1):
            B = self._rightshift(B - expanded_key[2 * i + 1], A, w) ^ A
            A = self._rightshift((A - expanded_key[2 * i]), B, w) ^ B
        B = (B - expanded_key[1]) % mod
        A = (A - expanded_key[0]) % mod
        res = A.to_bytes(b // 2, byteorder="little") + B.to_bytes(b // 2, byteorder="little")
        return res