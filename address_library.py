import struct
import sys
import os

class VersionDb:
    def __init__(self):
        self.data = {}  # id -> offset
        self.ver = [0, 0, 0, 0]
        self.module_name = ""
        self.ptr_size = 0

    def load(self, file_path):
        if not os.path.exists(file_path):
            print(f"Error: File not found: {file_path}")
            return False

        with open(file_path, "rb") as f:
            # Read format
            fmt_bytes = f.read(4)
            if not fmt_bytes: return False
            fmt = struct.unpack("<i", fmt_bytes)[0]

            if fmt not in [1, 2]:
                print(f"Error: Unsupported format {fmt}")
                return False

            # Read version
            self.ver = list(struct.unpack("<4i", f.read(16)))

            # Read module name
            tn_len = struct.unpack("<i", f.read(4))[0]
            if tn_len > 0:
                self.module_name = f.read(tn_len).decode('ascii')
            
            # Read ptr size
            self.ptr_size = struct.unpack("<i", f.read(4))[0]

            # Read addr count
            addr_count = struct.unpack("<i", f.read(4))[0]

            pvid = 0
            poffset = 0

            for _ in range(addr_count):
                type_byte = struct.unpack("<B", f.read(1))[0]
                low = type_byte & 0xF
                high = type_byte >> 4

                # Get ID (q1)
                if low == 0:
                    q1 = struct.unpack("<Q", f.read(8))[0]
                elif low == 1:
                    q1 = pvid + 1
                elif low == 2:
                    q1 = pvid + struct.unpack("<B", f.read(1))[0]
                elif low == 3:
                    q1 = pvid - struct.unpack("<B", f.read(1))[0]
                elif low == 4:
                    q1 = pvid + struct.unpack("<H", f.read(2))[0]
                elif low == 5:
                    q1 = pvid - struct.unpack("<H", f.read(2))[0]
                elif low == 6:
                    q1 = struct.unpack("<H", f.read(2))[0]
                elif low == 7:
                    q1 = struct.unpack("<I", f.read(4))[0]
                else:
                    return False

                # Get Offset (q2)
                tpoffset = poffset // self.ptr_size if (high & 8) != 0 else poffset

                high_type = high & 7
                if high_type == 0:
                    q2 = struct.unpack("<Q", f.read(8))[0]
                elif high_type == 1:
                    q2 = tpoffset + 1
                elif high_type == 2:
                    q2 = tpoffset + struct.unpack("<B", f.read(1))[0]
                elif high_type == 3:
                    q2 = tpoffset - struct.unpack("<B", f.read(1))[0]
                elif high_type == 4:
                    q2 = tpoffset + struct.unpack("<H", f.read(2))[0]
                elif high_type == 5:
                    q2 = tpoffset - struct.unpack("<H", f.read(2))[0]
                elif high_type == 6:
                    q2 = struct.unpack("<H", f.read(2))[0]
                elif high_type == 7:
                    q2 = struct.unpack("<I", f.read(4))[0]
                else:
                    return False

                if (high & 8) != 0:
                    q2 *= self.ptr_size

                self.data[q1] = q2
                pvid = q1
                poffset = q2

        return True

    def get_offset(self, id):
        return self.data.get(id)

def main():
    if len(sys.argv) < 3:
        print("Usage: python address_library.py <bin_file> <id1> [id2 ...]")
        return

    bin_file = sys.argv[1]
    ids = [int(x) for x in sys.argv[2:]]

    db = VersionDb()
    if db.load(bin_file):
        print(f"Loaded {bin_file} (Version: {'.'.join(map(str, db.ver))})")
        for id_val in ids:
            offset = db.get_offset(id_val)
            if offset is not None:
                print(f"ID {id_val} -> Offset 0x{offset:X}")
            else:
                print(f"ID {id_val} -> Not found")

if __name__ == "__main__":
    main()
