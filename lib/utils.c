#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

void generate_header(const char *input_file, const char *output_file, const char *var_name) {
    FILE *in = fopen(input_file, "rb");
    if (!in) {
        perror("Error opening input file");
        exit(EXIT_FAILURE);
    }

    FILE *out = fopen(output_file, "w");
    if (!out) {
        perror("Error creating output file");
        fclose(in);
        exit(EXIT_FAILURE);
    }

    fprintf(out, "#ifndef GENERATED_HEADER_H\n");
    fprintf(out, "#define GENERATED_HEADER_H\n\n");

    fseek(in, 0, SEEK_END);
    long file_size = ftell(in);
    fseek(in, 0, SEEK_SET);

    fprintf(out, "const unsigned char %s[%ld] = {\n", var_name, file_size);

    int byte;
    size_t count = 0;
    while ((byte = fgetc(in)) != EOF) {
        fprintf(out, "0x%02X,", (unsigned char)byte);
        count++;
        if (count % 12 == 0) {
            fprintf(out, "\n");
        }
    }

    fprintf(out, "\n};\n");
    fprintf(out, "\n#endif // GENERATED_HEADER_H\n");

    fclose(in);
    fclose(out);
}
