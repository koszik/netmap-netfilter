char *cpu_possible_mask;
void *calloc(int size, int nmemb);

void cpumask_init() {
    cpu_possible_mask = calloc(1, 512);
    cpu_possible_mask[0] = 1;
}
