#include "config.h"
#include "server.h"

int main(int argc, char **argv)
{
    const char *config_path = argc > 1 ? argv[1] : "tacacs.conf";

    tac_config_t cfg;
    if (tac_config_load(config_path, &cfg) != 0) {
        return 1;
    }

    int rc = tac_server_run(&cfg);

    tac_config_free(&cfg);
    return rc == 0 ? 0 : 1;
}
