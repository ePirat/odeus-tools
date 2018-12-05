#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

static inline uint8_t is_big_endian()
{
    const uint16_t endianness = 256;
    return *(const uint8_t *)&endianness;
}

#define ATTR_PACKED __attribute__((__packed__))

#define ODEUS_HEADER_SIZE 32

typedef struct ATTR_PACKED odeusHeader {
    uint32_t    magic;
    uint32_t    payload_size;
    uint32_t    field_8;
    uint32_t    type;
    uint64_t    field_10;
    uint64_t    sequence_number;
} odeus_header_t;


#define ODEUS_WAV_HEADER_SIZE 28

typedef struct ATTR_PACKED odeusWaveHeader {
    // WAVEFORMATEX
    uint16_t    wFormatTag;
    uint16_t    nChannels;
    uint32_t    nSamplesPerSec;
    uint32_t    nAvgBytesPerSec;
    uint16_t    nBlockAlign;
    uint16_t    wBitsPerSample;
    uint16_t    cbSize;
    // O-Deus additions
    uint16_t    unusedPadding;
    uint32_t    field_34;
    uint32_t    field_38;
} odeus_wave_header_t;

#define DECL_READ_TYPE(type) \
type read_##type(char **buf, size_t *size) \
{ \
    if (*size < sizeof(type)) \
        return 0; \
    type tmp; \
    memcpy(&tmp, *buf, sizeof(type));\
    *buf += sizeof(type);\
    *size -= sizeof(type);\
    return tmp; \
}

DECL_READ_TYPE(uint16_t);
DECL_READ_TYPE(uint32_t);
DECL_READ_TYPE(uint64_t);

uint64_t ntoh64(const uint64_t *input)
{
    uint64_t rval;
    char *data = (char *)&rval;

    data[0] = *input >> 56;
    data[1] = *input >> 48;
    data[2] = *input >> 40;
    data[3] = *input >> 32;
    data[4] = *input >> 24;
    data[5] = *input >> 16;
    data[6] = *input >> 8;
    data[7] = *input >> 0;

    return rval;
}

void odeus_header_swap(odeus_header_t *header_out)
{
    //header_out->magic = 
}

int odeus_header_read(int fildes, odeus_header_t *header_out)
{
    char *buffer = calloc(ODEUS_HEADER_SIZE, 1);
    size_t data_read = 0;

    do {
        ssize_t ret = read(fildes, buffer, ODEUS_HEADER_SIZE);

        if (ret < 0)
            return -errno;

        if (ret == 0)
            return 1;

        data_read += ret;
    } while (data_read < ODEUS_HEADER_SIZE);

    header_out->magic = read_uint32_t(&buffer, &data_read);
    if (header_out->magic != 0xDEEDBEE0)
        return -EPROTO;

    header_out->payload_size = read_uint32_t(&buffer, &data_read);
    header_out->field_8      = read_uint32_t(&buffer, &data_read);
    header_out->type         = read_uint32_t(&buffer, &data_read);

    header_out->field_10         = read_uint64_t(&buffer, &data_read);
    header_out->sequence_number  = read_uint64_t(&buffer, &data_read);

    return 0;
}

/** Print Odeus packet header
 */
void odeus_header_print(FILE *stream, odeus_header_t header)
{
    fprintf(stream,
        "O-Deus header:\n"
        "  magic:           %X\n"
        "  payload_size:    %u\n"
        "  field_8:         %u\n"
        "  type:            %u\n"
        "  field_10:        %llu\n"
        "  sequence_number: %llu\n",
        header.magic,
        header.payload_size,
        header.field_8,
        header.type,
        header.field_10,
        header.sequence_number
    );
}

char *odeus_decompress_2(char *buf, size_t rsize, size_t *out_size)
{
    size_t growth = rsize;      // Amount of bytes to grow out buffer
    size_t wsize = rsize * 2;   // Initial write buffer size

    unsigned char *rbuf = (unsigned char*)buf;
    unsigned char *wbuf = malloc(wsize); // Initial write buffer

    if (wbuf == NULL)
        return NULL;

    size_t rcnt = 0; // Read count
    size_t wcnt = 0; // Write count

    // Read our first control byte, and filter off the bits
    // that tell the wrapper code which decompressor to use
    uint8_t control = rbuf[rcnt++] & 0x1F;

    while (rcnt < rsize && wcnt < wsize) {
        if (control < 0x20) {
            // Literal copy
            for (uint8_t i = 0; i < control + 1; i++) {
                wbuf[wcnt++] = rbuf[rcnt++];
            }
        } else {
            // LZ copy
            size_t offset = (control & 0x1F) * 256;
            size_t write_count = (control >> 5);

            if (write_count == 7) {
                // Allow larger write counts
                uint8_t next_byte;
                do {
                    next_byte = rbuf[rcnt++];
                    write_count += next_byte;
                } while (next_byte == 255);
            }

            offset += rbuf[rcnt++];
            if (offset == 0x1FFF) {
                // Allow offsets even bigger than 0x1FFF
                // (This may be wrong!)
                offset += ((rbuf[rcnt] << 8) | rbuf[rcnt + 1]);
                rcnt += 2;
            }

            // Now the actual copying
            for (size_t i = 0; i < write_count + 2; i++) {
                size_t backref = wcnt - offset - 1;
                // Check for over/underflow
                if (backref > wcnt) {
                    free(wbuf);
                    return NULL;
                }

                wbuf[wcnt] = wbuf[backref];
                wcnt++;

                if (wcnt + 1 >= wsize) {
                    // Resize buffer
                    wsize += growth;
                    void *tmp = realloc(wbuf, wsize);
                    if (tmp == NULL) {
                        free(wbuf);
                        return NULL;
                    }
                    wbuf = tmp;
                }
            }
        }

        // Prepare for the next turn
        if (rcnt >= rsize)
            break;

        if (wcnt + 1 >= wsize) {
            // Resize buffer
            wsize += growth;
            void *tmp = realloc(wbuf, wsize);
            if (tmp == NULL) {
                free(wbuf);
                return NULL;
            }
            wbuf = tmp;
        }

        control = rbuf[rcnt++];
    }

    *out_size = wcnt;
    return (char*)wbuf;
}

char* odeus_decompress_payload(char *blob, size_t size, size_t *out_size)
{
    uint8_t first_thing = (blob[0] >> 5) + 1;

    if (first_thing == 2)
        return odeus_decompress_2(blob, size, out_size);
    else
        return NULL;
}

int main(int argc, char const *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int fp = open(argv[1], O_RDONLY);

    if (fp < 0) {
        perror("File opening failed");
        return EXIT_FAILURE;
    }

    odeus_header_t header;

    while (true) {

        int err = odeus_header_read(fp, &header);
        if (err == 1) {
            // EOF
            break;
        }
        if (err != 0) {
            fprintf(stderr, "Failed reading odeus header!\n");
            return EXIT_FAILURE;
        }
        
        odeus_header_print(stdout, header);

        // Read payload
        size_t size = header.payload_size;
        char *payload = malloc(size);
        do {
            ssize_t ret = read(fp, payload, size);

            if (ret < 0) {
                perror("Failed reading payload");
                return EXIT_FAILURE;
            }

            size -= ret;
        } while (size > 0);

        // Only PCM data is compressed, skip for everything else
        if (header.type != 0)
            continue;

        size_t decomp_size = 0;
        char *decomp_payload = odeus_decompress_payload(payload,
            header.payload_size, &decomp_size);

        if (decomp_payload != NULL) {
            fprintf(stdout, "Decompressed payload size %zu\n", decomp_size);

            // Read channel mapping
            int16_t channel_map[16];
            memcpy(channel_map, decomp_payload, 16 * sizeof(int16_t));
            fprintf(stdout, "Channel mapping: \n"
                "[%i %i %i %i %i %i %i %i %i %i %i %i %i %i %i %i]\n",
                channel_map[0], channel_map[1], channel_map[2], channel_map[3],
                channel_map[4], channel_map[5], channel_map[6], channel_map[7],
                channel_map[8], channel_map[9], channel_map[10], channel_map[11],
                channel_map[12], channel_map[13], channel_map[14], channel_map[15]);

            // Remove channel mapping from data
            decomp_payload += 16 * sizeof(int16_t);
            decomp_size -= 16 * sizeof(int16_t);

            if (argc > 2) {
                const char *outpath = argv[2];
                FILE *of = fopen(outpath, "ab");
                if (of == NULL) {
                    perror("Failed opening output file");
                    return EXIT_FAILURE;
                }

                if (fwrite(decomp_payload, decomp_size, 1, of) != 1) {
                    perror("Failed writing to output file");
                    return EXIT_FAILURE;
                }
                fclose(of);
            }
        } else {
            fprintf(stderr, "Failed decompressing payload!\n");
        }

        free(payload);

    }

    close(fp);
    return 0;
}
