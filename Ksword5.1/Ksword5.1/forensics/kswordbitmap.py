"""Read-only Volatility physical layer for Windows x64 SDMP kernel bitmap dumps (type 6)."""
import struct

from volatility3.framework import exceptions, interfaces
from volatility3.framework.layers import segmented

BIT_COUNTS = bytes(bin(i).count("1") for i in range(256))

def bitmap_segments(bitmap, bits, count, data_at, file_size):
    if not bits or len(bitmap) != (bits + 7) // 8 or count > bits:
        raise ValueError("invalid bitmap size")
    if bits % 8 and bitmap[-1] >> (bits % 8):
        raise ValueError("nonzero bits beyond last PFN")
    if data_at % 4096 or data_at + count * 4096 > file_size:
        raise ValueError("bitmap payload exceeds file")
    if sum(bitmap.translate(BIT_COUNTS)) != count:
        raise ValueError("bitmap population does not match published page count")
    segments = []
    first = None
    start_in_file = cursor = data_at
    for byte_no, byte in enumerate(bitmap):
        index = 8 * byte_no
        if byte == 0xFF:
            if first is None:
                first, start_in_file = index, cursor
            cursor += 8 * 4096
            continue
        if byte == 0 and first is None:
            continue
        for bit in range(min(8, bits - index)):
            if byte & (1 << bit):
                if first is None:
                    first, start_in_file = index + bit, cursor
                cursor += 4096
            elif first is not None:
                if len(segments) >= 2 * 1024 * 1024:
                    raise ValueError("excessively fragmented bitmap")
                length = cursor - start_in_file
                segments.append((first * 4096, start_in_file, length, length))
                first = None
    if first is not None:
        length = cursor - start_in_file
        segments.append((first * 4096, start_in_file, length, length))
    if not segments or cursor != data_at + count * 4096:
        raise ValueError("bitmap population does not match published page count")
    return segments


class KswordKernelBitmapLayer(segmented.SegmentedLayer):
    provides = {"type": "physical"}

    def __init__(self, context, config_path, name, metadata=None):
        layer = context.layers[context.config[interfaces.configuration.path_join(config_path, "base_layer")]]
        dtb = struct.unpack("<Q", layer.read(0x10, 8))[0] & 0x000FFFFFFFFFF000
        if not dtb:
            raise ValueError("dump header has no DTB")
        super().__init__(context, config_path, name,
                         metadata={"os": "Windows", "architecture": "Intel64", "page_map_offset": dtb})
        if not self.is_valid(dtb, 4096):
            raise ValueError("dump header DTB is not present in captured RAM")

    def _load_segments(self):
        base = self.context.layers[self._base_layer]
        header = base.read(0x2000, 56)
        if header[:8] != b"SDMPDUMP":
            raise ValueError("unsupported type-6 bitmap header")
        data_at, count, bits = struct.unpack_from("<QQQ", header, 0x20)
        bitmap_bytes = (bits + 7) // 8
        if not (0x2038 + bitmap_bytes <= data_at <= base.maximum_address + 1) or bitmap_bytes > 256 * 1024 * 1024:
            raise ValueError("invalid bitmap header boundary")
        self._segments = bitmap_segments(base.read(0x2038, bitmap_bytes), bits, count, data_at, base.maximum_address + 1)


class KswordKernelBitmapStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10

    @classmethod
    def stack(cls, context, layer_name, progress_callback=None):
        base = context.layers[layer_name]
        try:
            if base.read(0, 8) != b"PAGEDU64" or base.read(0xF98, 4) != b"\x06\0\0\0":
                return None
            if base.read(0x30, 4) != b"\x64\x86\0\0":
                return None
            name = context.layers.free_layer_name("KswordKernelBitmap")
            context.config[interfaces.configuration.path_join(name, "base_layer")] = layer_name
            return KswordKernelBitmapLayer(context, name, name)
        except (exceptions.InvalidAddressException, ValueError, struct.error):
            return None
