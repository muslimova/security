from RC5.Chipher.Chipher import Cipher

class RC5(Cipher):
    def __init__(self, key, block_size, rounds):
        self.key = key
        self.block_size = block_size
        self.rounds = rounds

    def encrypt(self, data):
        block_size = self.block_size
        key = self.key
        rounds = self.rounds
        w = block_size // 2
        b = block_size // 8
        expanded_key = Cipher._expand_key(self, key, w, rounds)
        index = b
        piece = data[:index]
        out = []
        while piece:
            piece = piece.ljust(b, b"\x00")
            encrypted_piece = Cipher._encrypt_block(self, piece, expanded_key, block_size, rounds)
            out.append(encrypted_piece)
            piece = data[index: index + b]
            index += b
        return b"".join(out)

    def decrypt(self, data):
        block_size = self.block_size
        key = self.key
        rounds = self.rounds
        w = block_size // 2
        b = block_size // 8
        expanded_key = Cipher._expand_key(self, key, w, rounds)
        index = b
        piece = data[:index]
        out = []
        while piece:
            decrypted_piece = Cipher._decrypt_block(self, piece, expanded_key, block_size, rounds)
            piece = data[index: index + b]
            if not piece:
                decrypted_piece = decrypted_piece.rstrip(b"\x00")
            index += b
            out.append(decrypted_piece)
        return b"".join(out)
