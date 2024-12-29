#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <openssl/evp.h>

#include "net.h"
#include "util.h"

extern FILE *netLog;
extern FILE *gxLog;

void es_NetCommand(NetCommand* command) {
    command->cmdid = SWAP_LE(command->cmdid);
	
	//allow swap and reswap
	uint32_t cmdid = command->cmdid;
	if(cmdid > 0x1000) {
		printf("RESWAP");
		cmdid = SWAP_LE(cmdid);
		if(cmdid > 0x1000) {	
			fprintf(stderr, "cmdid too big\n");
			return;
		}
	}
    switch (cmdid) {
        case 0x02: case 0x04: case 0x07: case 0x0D: case 0x0E: case 0x11:
        case 0x15: case 0x1F: case 0x21: case 0x28: case 0x2C:
        case 0x2E: case 0x2F: case 0x3D: case 0x3F:
        case 0x43: case 0x4D:
        case 0x17: case 0x1C: case 0x1D: case 0x1E:
		{
            command->oneU32.param = SWAP_LE(command->oneU32.param);
            break;
		}
        case 0x01:
		{
            command->cmd_01.offset = SWAP_LE(command->cmd_01.offset);
            command->cmd_01.hackid = SWAP_LE(command->cmd_01.hackid);
            break;
		}
        case 0x0F: case 0x10: case 0x26: case 0x27:
        case 0x29: case 0x48: case 0x4C:
		{
            command->twoU32.param1 = SWAP_LE(command->twoU32.param1);
            command->twoU32.param2 = SWAP_LE(command->twoU32.param2);
            break;
		}
        case 0x08:
		{
            command->cmd_08.ReplaceDataMask = SWAP_LE(command->cmd_08.ReplaceDataMask);
            command->cmd_08.ReplaceData = SWAP_LE(command->cmd_08.ReplaceData);
            command->cmd_08.OriginalDataMask = SWAP_LE(command->cmd_08.OriginalDataMask);
            command->cmd_08.OriginalData = SWAP_LE(command->cmd_08.OriginalData);
            break;
		}
        case 0x09:
		{
            command->cmd_09.count = SWAP_LE(command->cmd_09.count);
			uint32_t count = command->cmd_09.count;
			if( count > 0x1000 ) {
				count = SWAP_LE(count);
				if(count > 0x1000) {
					fprintf(stderr, "cmd_09 count too big\n");
					return;
				}
			}
            for (uint32_t i = 0; i < count; i++) {
                command->cmd_09.data[i].offset = SWAP_LE(command->cmd_09.data[i].offset);
            }
            break;
		}
        case 0x0A:
		{
            command->cmd_0A.count = SWAP_LE(command->cmd_0A.count);
			uint32_t count = command->cmd_0A.count;
			if( count > 0x1000 ) {
				count = SWAP_LE(count);
				if(count > 0x1000) {
					fprintf(stderr, "cmd_0A count too big\n");
					return;
				}
			}
            for (uint32_t i = 0; i < count; i++) {
                command->cmd_0A.data[i].offset = SWAP_LE(command->cmd_0A.data[i].offset);
            }
            break;
		}
        case 0x0B:
		{
            command->cmd_0B.count = SWAP_LE(command->cmd_0B.count);
			uint32_t count = command->cmd_0B.count;
			if( count > 0x1000 ) {
				count = SWAP_LE(count);
				if(count > 0x1000) {
					fprintf(stderr, "cmd_0B count too big\n");
					return;
				}
			}
            for (uint32_t i = 0; i < count; i++) {
                command->cmd_0B.data[i].sector = SWAP_LE(command->cmd_0B.data[i].sector);
                command->cmd_0B.data[i].offset = SWAP_LE(command->cmd_0B.data[i].offset);
                command->cmd_0B.data[i].size = SWAP_LE(command->cmd_0B.data[i].size);
            }
            break;
		}
        case 0x0C:
		{
            command->twoU16.param1 = SWAP_LE(command->twoU16.param1);
            command->twoU16.param2 = SWAP_LE(command->twoU16.param2);
            break;
		}
        case 0x12:
		{
            command->oneArrayU32.count = SWAP_LE(command->oneArrayU32.count);
			uint32_t count = command->oneArrayU32.count;
			if( count > 0x1000 ) {
				count = SWAP_LE(count);
				if(count > 0x1000) {
					fprintf(stderr, "oneArrayU32 count too big\n");
					return;
				}
			}
            for (uint32_t i = 0; i < count; i++) {
                command->oneArrayU32.paramArray[i] = SWAP_LE(command->oneArrayU32.paramArray[i]);
            }
            break;
		}
        case 0x13: case 0x20: case 0x24:
		{
            command->oneU64.param = SWAP_LE(command->oneU64.param);
            break;
		}
        case 0x42:
		{
            command->cmd_42.offset = SWAP_LE(command->cmd_42.offset);
            command->cmd_42.count = SWAP_LE(command->cmd_42.count);
			uint32_t count = command->cmd_42.count;
			if( count > 0x1000 ) {
				count = SWAP_LE(count);
				if(count > 0x1000) {
					fprintf(stderr, "cmd_42 count too big\n");
					return;
				}
			}
            for (uint32_t i = 0; i < count; i++) {
                command->cmd_42.param[i] = SWAP_LE(command->cmd_42.param[i]);
            }
            break;
		}
        case 0x4B:
		{
            command->cmd_4B.offset = SWAP_LE(command->cmd_4B.offset);
            command->cmd_4B.Redirect = SWAP_LE(command->cmd_4B.Redirect);
            break;
		}
        default:
		{
            break;
		}
    }
}

int load_NetCfg(const char* filename, NetCfg_t* cfg) {
    int ret=-1;
	
	FILE* file = fopen(filename, "rb");
    if (!file) {
        perror("Error opening file");
        return -1;
    }

	memset(cfg, 0, sizeof(NetCfg_t));

    uint32_t cmdid;

	cfg->commands = calloc(0x400000, 1);
	if (!cfg->commands) {
		perror("malloc allocation failed");
		goto end;
	}
	
    while (fread(&cmdid, sizeof(uint32_t), 1, file) == 1) {
		
		/* doesn't work, size prob not good, I used huge malloc before the loop instead
		cfg->commands = realloc(cfg->commands, (cfg->cmdCount + 1) * sizeof(NetCommand));
        if (!cfg->commands) {
            perror("realloc allocation failed");
            goto end;
        }
		*/

        cfg->commands[cfg->cmdCount].cmdid = cmdid;
		cmdid = SWAP_LE(cmdid);
		switch (cmdid) {
			case 0x03: case 0x05: case 0x06: case 0x14:
			case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x22:
			case 0x23: case 0x2A: case 0x2B: case 0x2D:
			case 0x35: case 0x3E: case 0x40: case 0x41: case 0x44:
			case 0x45: case 0x46: case 0x47: case 0x49: case 0x4A:
			case 0x50: case 0x16: case 0x25:
			{
				break;
			}
			case 0x02: case 0x04: case 0x07: case 0x0D: case 0x0E: case 0x11:
			case 0x15: case 0x1F: case 0x21: case 0x28: case 0x2C:
			case 0x2E: case 0x2F: case 0x3D: case 0x3F:
			case 0x43: case 0x4D: 
			case 0x17: case 0x1C: case 0x1D: case 0x1E:
			{
                if (fread(&cfg->commands[cfg->cmdCount].oneU32.param, sizeof(uint32_t), 1, file) != 1) {
                    perror("Error reading parameter for cmdid 0x04");
                    goto end;
                }
				break;
			}
            case 0x01:
			{
                if (fread(&cfg->commands[cfg->cmdCount].cmd_01.offset, sizeof(uint32_t), 1, file) != 1 ||
                    fread(&cfg->commands[cfg->cmdCount].cmd_01.hackid, sizeof(uint32_t), 1, file) != 1) {
                    perror("Error reading cmd_01 data");
                    goto end;
                }
				break;
			}
            case 0x0F: case 0x10: case 0x26: case 0x27:
			case 0x29: case 0x48: case 0x4C:
			{
                if (fread(&cfg->commands[cfg->cmdCount].twoU32.param1, sizeof(uint32_t), 1, file) != 1 ||
                    fread(&cfg->commands[cfg->cmdCount].twoU32.param2, sizeof(uint32_t), 1, file) != 1) {
                    perror("Error reading twoU32 parameters");
                    goto end;
                }
                break;
			}
            case 0x00:
			{
				// optional no need to check
                fread(&cfg->commands[cfg->cmdCount].cmd_00.titleID, sizeof(char), 10, file);
				
				// no need to swap
				//es_NetCommand(&cfg->commands[cfg->cmdCount]);
        		cfg->cmdCount++;
				goto last_cmd;
                break;
			}
            case 0x08:
			{
                if (fread(&cfg->commands[cfg->cmdCount].cmd_08.ReplaceDataMask, sizeof(uint64_t), 1, file) != 1 ||
                    fread(&cfg->commands[cfg->cmdCount].cmd_08.ReplaceData, sizeof(uint64_t), 1, file) != 1 ||
                    fread(&cfg->commands[cfg->cmdCount].cmd_08.OriginalDataMask, sizeof(uint64_t), 1, file) != 1 ||
                    fread(&cfg->commands[cfg->cmdCount].cmd_08.OriginalData, sizeof(uint64_t), 1, file) != 1) {
                    perror("Error reading cmd_08 data");
                    goto end;
                }
                break;
			}
            case 0x09:
			{
                uint32_t count;
                if (fread(&count, sizeof(uint32_t), 1, file) != 1) {
					perror("Error reading cmd_09 count");
                    goto end;
				}
				cfg->commands[cfg->cmdCount].cmd_09.count = count;
				count = SWAP_LE(count);
                for (uint32_t i = 0; i < count; i++) {
                    fread(&cfg->commands[cfg->cmdCount].cmd_09.data[i].offset, sizeof(uint32_t), 1, file);
                    fread(&cfg->commands[cfg->cmdCount].cmd_09.data[i].OriginalData, sizeof(uint8_t), 8, file);
                    fread(&cfg->commands[cfg->cmdCount].cmd_09.data[i].ReplaceData, sizeof(uint8_t), 8, file);
                }
                break;
			}
            case 0x0A:
			{
                uint32_t count;
                if(fread(&count, sizeof(uint32_t), 1, file) != 1) {
					perror("Error reading cmd_0A count");
                    goto end;
				}
				cfg->commands[cfg->cmdCount].cmd_0A.count = count;
				count = SWAP_LE(count);
                for (uint32_t i = 0; i < count; i++) {
                    if( fread(&cfg->commands[cfg->cmdCount].cmd_0A.data[i].offset, sizeof(uint32_t), 1, file) != 1 ||
						fread(cfg->commands[cfg->cmdCount].cmd_0A.data[i].OriginalData, sizeof(uint8_t), 4, file) != 4 ||
						fread(cfg->commands[cfg->cmdCount].cmd_0A.data[i].ReplaceData, sizeof(uint8_t), 4, file) != 4 ) {
						fprintf(stderr, "Error reading cmd_0A data %X\n", i);
						goto end;
					}
                }
                break;
			}
            case 0x0B:
			{
				
                uint32_t count;
                if(fread(&count, sizeof(uint32_t), 1, file) != 1) {
					perror("Error reading cmd_0B count");
                    goto end;
				}
				cfg->commands[cfg->cmdCount].cmd_0B.count = count;
				count = SWAP_LE(count);
				for (uint32_t i = 0; i < count; i++) {
                    
                    if( fread(&cfg->commands[cfg->cmdCount].cmd_0B.data[i].sector, sizeof(uint32_t), 1, file) != 1 ||
						fread(&cfg->commands[cfg->cmdCount].cmd_0B.data[i].offset, sizeof(uint32_t), 1, file) != 1) {
						perror("Error reading cmd_0A offset/sector");
						goto end;
					}
					uint32_t size;
                    if( fread(&size, sizeof(uint32_t), 1, file) != 1) {
						perror("Error reading cmd_0A size");
						goto end;
					}
                    cfg->commands[cfg->cmdCount].cmd_0B.data[i].size = size;
					size = SWAP_LE(size);

					/* too much issue with it
					cfg->commands[cfg->cmdCount].cmd_0B.data[i].ReplaceData = malloc(size);
					cfg->commands[cfg->cmdCount].cmd_0B.data[i].OriginalData = malloc(size);
					if (!cfg->commands[cfg->cmdCount].cmd_0B.data[i].ReplaceData || !cfg->commands[cfg->cmdCount].cmd_0B.data[i].OriginalData) {
						perror("Failed to allocate memory for ReplaceData or OriginalData");
						goto end;
					}
					*/
					
					
                    if( fread(cfg->commands[cfg->cmdCount].cmd_0B.data[i].ReplaceData, sizeof(uint8_t), size, file) != size) {
						perror("Error reading cmd_0B ReplaceData or OriginalData");
						goto end;
					}	
						
					if( fread(cfg->commands[cfg->cmdCount].cmd_0B.data[i].OriginalData, sizeof(uint8_t), size, file) != size ) {
						perror("Error reading cmd_0B OriginalData");
						goto end;
					}
                }
                break;
			}
            case 0x0C:
			{
                if( fread(&cfg->commands[cfg->cmdCount].twoU16, sizeof(uint16_t), 2, file) != 2) {
					perror("Error reading twoU16");
                    goto end;
				}
                break;
			}
            case 0x12:
			{
                uint32_t count;
                if( fread(&count, sizeof(uint32_t), 1, file) != 1) {
					perror("Error reading oneArrayU32 count");
                    goto end;
				}
				cfg->commands[cfg->cmdCount].oneArrayU32.count = count;
				count = SWAP_LE(count);
                if( fread(cfg->commands[cfg->cmdCount].oneArrayU32.paramArray, sizeof(uint32_t), count, file) != count) {
					perror("Error reading oneArrayU32 data");
                    goto end;
				}
                break;
			}
            case 0x13: case 0x20: case 0x24:
			{
                fread(&cfg->commands[cfg->cmdCount].oneU64.param, sizeof(uint64_t), 1, file);
                break;
			}
			case 0x42:
			{
                if( fread(&cfg->commands[cfg->cmdCount].cmd_42.offset, sizeof(uint32_t), 1, file) != 1) {
					perror("Error reading cmd_42 offset");
                    goto end;
				}

				uint32_t count;
                if( fread(&count, sizeof(uint32_t), 1, file) != 1) {
					perror("Error reading cmd_42 count");
                    goto end;
				}
				cfg->commands[cfg->cmdCount].cmd_42.count = count;
				count = SWAP_LE(count);
				if( fread(cfg->commands[cfg->cmdCount].cmd_42.param, sizeof(uint32_t), count, file) != count) {
					perror("Error reading cmd_42 param");
					goto end;
				}
				
				break;
			}
			case 0x4B:
			{
                if( fread(&cfg->commands[cfg->cmdCount].cmd_4B.offset, sizeof(uint32_t), 1, file) != 1) {
					perror("Error reading cmd_42 offset");
                    goto end;
				}
                if( fread(&cfg->commands[cfg->cmdCount].cmd_4B.Redirect, sizeof(uint32_t), 1, file) != 1) {
					perror("Error reading cmd_42 Redirect");
                    goto end;
				}
				if( fread(&cfg->commands[cfg->cmdCount].cmd_4B.data, sizeof(char), 0x10, file) != 0x10) {
					perror("Error reading cmd_4B data");
					goto end;
				}
				break;
			}
            default:
			{
                fprintf(stderr, "Unknown cmdid: 0x%X | %s\n", cmdid, filename);
                break;
			}
        }
		es_NetCommand(&cfg->commands[cfg->cmdCount]);
        cfg->cmdCount++;
    }
last_cmd:
	ret=0;
	//optionnal extra data
	if (fread(&cfg->extra_data.unk, sizeof(uint8_t), 1, file) != 1) {
		goto end;
	}
	cfg->extra_size++;
	if(fread(&cfg->extra_data.disc_count, sizeof(uint8_t), 1, file) != 1) {
		goto end;
	}
	if( cfg->extra_data.disc_count == 0 ) {
		// it must be != 0
		fprintf(stderr, "extra_data disc_count==0 %s\n", filename);
		cfg->extra_size = 0;
		goto end;
	}
	cfg->extra_size++;
	if(fread(&cfg->extra_data.disc_index, sizeof(uint8_t), 1, file) != 1) {
		goto end;
	}
	cfg->extra_size++;
	if(fread(&cfg->extra_data.resetVM, sizeof(uint8_t), 1, file) != 1) {
		goto end;
	}
	cfg->extra_size++;
end:
    FCLOSE(file);
    return ret;
}

int save_NetCfg(const char* filename, NetCfg_t* cfg) {
    FILE* file = fopen(filename, "wb");
    if (!file) {
        perror("Error opening file for writing");
        return -1;
    }
	
	for (uint32_t i = 0; i < cfg->cmdCount; i++) {
		
		es_NetCommand(&cfg->commands[i]);

		if (fwrite(&cfg->commands[i].cmdid, sizeof(uint32_t), 1, file) != 1) {
            perror("Error writing cmdid");
            fclose(file);
            return -1;
        }

        switch (cfg->commands[i].cmdid) {
            case 0x03: case 0x05: case 0x06: case 0x14:
			case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x22:
			case 0x23: case 0x2A: case 0x2B: case 0x2D:
			case 0x35: case 0x3E: case 0x40: case 0x41: case 0x44:
			case 0x45: case 0x46: case 0x47: case 0x49: case 0x4A:
			case 0x50: case 0x16: case 0x25:
			{
				break;
			}
			case 0x02: case 0x04: case 0x07: case 0x0D: case 0x0E: case 0x11:
			case 0x15: case 0x1F: case 0x21: case 0x28: case 0x2C:
			case 0x2E: case 0x2F: case 0x3D: case 0x3F:
			case 0x43: case 0x4D:
			case 0x17: case 0x1C: case 0x1D: case 0x1E:
			{
				if (fwrite(&cfg->commands[i].oneU32.param, sizeof(uint32_t), 1, file) != 1) {
					perror("Error writing oneU32.param");
					fclose(file);
					return -1;
				}
				break;
			}
            case 0x01:
			{
                if (fwrite(&cfg->commands[i].cmd_01.offset, sizeof(uint32_t), 1, file) != 1 ||
                    fwrite(&cfg->commands[i].cmd_01.hackid, sizeof(uint32_t), 1, file) != 1) {
                    perror("Error writing cmd_01 data");
                    fclose(file);
                    return -1;
                }
                break;
			}
			case 0x0F: case 0x10: case 0x26: case 0x27:
			case 0x29: case 0x48: case 0x4C:
			{
                if (fwrite(&cfg->commands[i].twoU32.param1, sizeof(uint32_t), 1, file) != 1 ||
                    fwrite(&cfg->commands[i].twoU32.param2, sizeof(uint32_t), 1, file) != 1) {
                    perror("Error writing twoU32 parameters");
                    fclose(file);
                    return -1;
                }
                break;
			}
            case 0x00:
			{
				if( cfg->commands[i].cmd_00.titleID[0] != 0 ) {
					if(fwrite(cfg->commands[i].cmd_00.titleID, sizeof(char), 10, file) != 10) {
                        perror("Error writing cmd_00.titleID");
                        fclose(file);
                        return -1;
                    }
				}
				goto last_cmd;
                break;
			}
            case 0x08:
			{
				if (fwrite(&cfg->commands[i].cmd_08.ReplaceDataMask, sizeof(uint64_t), 1, file) != 1 ||
                    fwrite(&cfg->commands[i].cmd_08.ReplaceData, sizeof(uint64_t), 1, file) != 1 ||
                    fwrite(&cfg->commands[i].cmd_08.OriginalDataMask, sizeof(uint64_t), 1, file) != 1 ||
                    fwrite(&cfg->commands[i].cmd_08.OriginalData, sizeof(uint64_t), 1, file) != 1) {
                    perror("Error writing cmd_08 data");
                    fclose(file);
                    return -1;
                }
                break;
			}
            case 0x09:
			{
                if (fwrite(&cfg->commands[i].cmd_09.count, sizeof(uint32_t), 1, file) != 1) {
                    perror("Error writing cmd_09.count");
                    fclose(file);
                    return -1;
                }
                uint32_t count = SWAP_LE(cfg->commands[i].cmd_09.count);
                for (uint32_t j = 0; j < count; j++) {
                    if (fwrite(&cfg->commands[i].cmd_09.data[j].offset, sizeof(uint32_t), 1, file) != 1 ||
                        fwrite(cfg->commands[i].cmd_09.data[j].OriginalData, sizeof(uint8_t), 8, file) != 8 ||
                        fwrite(cfg->commands[i].cmd_09.data[j].ReplaceData, sizeof(uint8_t), 8, file) != 8) {
                        perror("Error writing cmd_09 data");
                        fclose(file);
                        return -1;
                    }
                }
                break;
			}
            case 0x0A:
			{
                if (fwrite(&cfg->commands[i].cmd_0A.count, sizeof(uint32_t), 1, file) != 1) {
                    perror("Error writing cmd_0A.count");
                    fclose(file);
                    return -1;
                }
                uint32_t count = SWAP_LE(cfg->commands[i].cmd_0A.count);
                for (uint32_t j = 0; j < count; j++) {
                    if (fwrite(&cfg->commands[i].cmd_0A.data[j].offset, sizeof(uint32_t), 1, file) != 1 ||
                        fwrite(cfg->commands[i].cmd_0A.data[j].OriginalData, sizeof(uint8_t), 4, file) != 4 ||
                        fwrite(cfg->commands[i].cmd_0A.data[j].ReplaceData, sizeof(uint8_t), 4, file) != 4) {
                        perror("Error writing cmd_0A data");
                        fclose(file);
                        return -1;
                    }
                }
                break;
			}
            case 0x0B:
			{
                if (fwrite(&cfg->commands[i].cmd_0B.count, sizeof(uint32_t), 1, file) != 1) {
                    perror("Error writing cmd_0B.count");
                    fclose(file);
                    return -1;
                }
                uint32_t count = SWAP_LE(cfg->commands[i].cmd_0B.count);
                for (uint32_t j=0; j < count; j++) {
                    if (fwrite(&cfg->commands[i].cmd_0B.data[j].sector, sizeof(uint32_t), 1, file) != 1 ||
                        fwrite(&cfg->commands[i].cmd_0B.data[j].offset, sizeof(uint32_t), 1, file) != 1 ||
                        fwrite(&cfg->commands[i].cmd_0B.data[j].size, sizeof(uint32_t), 1, file) != 1) {
                        perror("Error writing cmd_0B data");
                        fclose(file);
                        return -1;
                    }
                    uint32_t size = SWAP_LE(cfg->commands[i].cmd_0B.data[j].size);
                    if (fwrite(cfg->commands[i].cmd_0B.data[j].ReplaceData, sizeof(uint8_t), size, file) != size ||
                        fwrite(cfg->commands[i].cmd_0B.data[j].OriginalData, sizeof(uint8_t), size, file) != size) {
                        perror("Error writing cmd_0B data arrays");
                        fclose(file);
                        return -1;
                    }
                }
                break;
			}
            case 0x0C:
			{
                if (fwrite(&cfg->commands[i].twoU16.param1, sizeof(uint16_t), 1, file) != 1 ||
                    fwrite(&cfg->commands[i].twoU16.param2, sizeof(uint16_t), 1, file) != 1) {
                    perror("Error writing twoU16 parameters");
                    fclose(file);
                    return -1;
                }
                break;
			}
            case 0x12:
			{
				if (fwrite(&cfg->commands[i].oneArrayU32.count, sizeof(uint32_t), 1, file) != 1) {
                    perror("Error writing oneArrayU32.count");
                    fclose(file);
                    return -1;
                }
                uint32_t count = SWAP_LE(cfg->commands[i].oneArrayU32.count);
                if (fwrite(cfg->commands[i].oneArrayU32.paramArray, sizeof(uint32_t), count, file) != count) {
                    perror("Error writing oneArrayU32 data");
                    fclose(file);
                    return -1;
                }
                break;
			}
            case 0x13: case 0x20: case 0x24:
			{
                if (fwrite(&cfg->commands[i].oneU64.param, sizeof(uint64_t), 1, file) != 1) {
                    perror("Error writing oneU64.param");
                    fclose(file);
                    return -1;
                }
                break;
			}
			case 0x42:
			{
                if (fwrite(&cfg->commands[i].cmd_42.offset, sizeof(uint32_t), 1, file) != 1 ||
                    fwrite(&cfg->commands[i].cmd_42.count, sizeof(uint32_t), 1, file) != 1) {
                    perror("Error writing cmd_42 data");
                    fclose(file);
                    return -1;
                }
                uint32_t count = SWAP_LE(cfg->commands[i].cmd_42.count);
                if (fwrite(cfg->commands[i].cmd_42.param, sizeof(uint32_t), count, file) != count) {
                    perror("Error writing cmd_42.param");
                    fclose(file);
                    return -1;
                }
				
				break;
			}
			case 0x4B:
			{
                if (fwrite(&cfg->commands[i].cmd_4B.offset, sizeof(uint32_t), 1, file) != 1 ||
                    fwrite(&cfg->commands[i].cmd_4B.Redirect, sizeof(uint32_t), 1, file) != 1 ||
                    fwrite(&cfg->commands[i].cmd_4B.data, sizeof(char), 0x10, file) != 0x10) {
                    perror("Error writing cmd_4B data");
                    fclose(file);
                    return -1;
                }
                break;
			}
            default:
			{
                fprintf(stderr, "Unknown cmdid: 0x%X\n", cfg->commands[i].cmdid);
                break;
			}
        }
    }
last_cmd:
	//optionnal extra data
	if(cfg->extra_size != 0) {
		if(fwrite(&cfg->extra_data, sizeof(uint8_t), cfg->extra_size, file) != cfg->extra_size) {
			fprintf(stderr, "Error writing extra_data %s", filename);
			return -1;
		}
	}
    FCLOSE(file);
    return 0;
}

int NetCfg_to_txt(FILE* file, const NetCfg_t* cfg) {
	
    if (!file || !cfg) {
        return -1;
    }
	
	for (uint32_t i = 0; i < cfg->cmdCount; i++) {
		fprintf(file, "\t#%d cmdid: 0x%08X\n", i, cfg->commands[i].cmdid);
		
		switch (cfg->commands[i].cmdid) {
			case 0x03: case 0x05: case 0x06: case 0x14:
			case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x22:
			case 0x23: case 0x2A: case 0x2B: case 0x2D:
			case 0x35: case 0x3E: case 0x40: case 0x41: case 0x44:
			case 0x45: case 0x46: case 0x47: case 0x49: case 0x4A:
			case 0x50: case 0x16: case 0x25:
			{
				break;
			}
			case 0x02: case 0x04: case 0x07: case 0x0D: case 0x0E: case 0x11:
			case 0x15: case 0x1F: case 0x21: case 0x28: case 0x2C:
			case 0x2E: case 0x2F: case 0x3D: case 0x3F:
			case 0x43: case 0x4D: 
			case 0x17: case 0x1C: case 0x1D: case 0x1E:
			{
				fprintf(file, "\t\tparam: 0x%08X\n", cfg->commands[i].oneU32.param); 
				break;
			}
			case 0x0F: case 0x10: case 0x26: case 0x27:
			case 0x29: case 0x48: case 0x4C:
			{
				fprintf(file, "\t\tparam1: 0x%08X\n", cfg->commands[i].twoU32.param1);
				fprintf(file, "\t\tparam2: 0x%08X\n", cfg->commands[i].twoU32.param2);
				break;
			}
			case 0x01:
			{
				fprintf(file, "\t\toffset: 0x%08X\n", cfg->commands[i].cmd_01.offset);
				fprintf(file, "\t\thackid: 0x%08X\n", cfg->commands[i].cmd_01.hackid);
				break;
			}
			case 0x00:
			{
				fprintf(file, "\t\ttitleID: %.10s\n", cfg->commands[i].cmd_00.titleID);
				break;
			}
			case 0x08:
			{
				fprintf(file, "\t\tReplaceDataMask: 0x%016llX\n", cfg->commands[i].cmd_08.ReplaceDataMask);
				fprintf(file, "\t\tReplaceData: 0x%016llX\n", cfg->commands[i].cmd_08.ReplaceData);
				fprintf(file, "\t\tOriginalDataMask: 0x%016llX\n", cfg->commands[i].cmd_08.OriginalDataMask);
				fprintf(file, "\t\tOriginalData: 0x%016llX\n", cfg->commands[i].cmd_08.OriginalData);
				break;
			}
			case 0x09:
			{
				fprintf(file, "\t\tcount: 0x%08X\n", cfg->commands[i].cmd_09.count);
				for (uint32_t j = 0; j < cfg->commands[i].cmd_09.count; j++) {
					fprintf(file, "\t\t\toffset: 0x%08X\n", cfg->commands[i].cmd_09.data[j].offset);
					
					fprintf(file, "\t\t\tOriginalData:\n");
					write_data(file, cfg->commands[i].cmd_09.data[j].OriginalData, 8, 0, 5);
				
					fprintf(file, "\t\t\tReplaceData:\n");
					write_data(file, cfg->commands[i].cmd_09.data[j].ReplaceData, 8, 0, 5);
				}
				break;
			}
			case 0x0A:
			{
				fprintf(file, "\t\tcount: 0x%08X\n", cfg->commands[i].cmd_0A.count);
				for (uint32_t j = 0; j < cfg->commands[i].cmd_0A.count; j++) {
					fprintf(file, "\t\t\toffset: 0x%08X\n", cfg->commands[i].cmd_0A.data[j].offset);
					
					fprintf(file, "\t\t\tOriginalData:\n");
					write_data(file, cfg->commands[i].cmd_0A.data[j].OriginalData, 4, 0, 5);
					
					fprintf(file, "\t\t\tReplaceData:\n");
					write_data(file, cfg->commands[i].cmd_0A.data[j].ReplaceData, 4, 0, 5);
				}
				break;
			}
			case 0x0B:
			{
				fprintf(file, "\t\tcount: 0x%08X\n", cfg->commands[i].cmd_0B.count);
				for (uint32_t j = 0; j < cfg->commands[i].cmd_0B.count; j++) {
					fprintf(file, "\t\t\tsector: 0x%08X\n", cfg->commands[i].cmd_0B.data[j].sector);
					fprintf(file, "\t\t\toffset: 0x%08X\n", cfg->commands[i].cmd_0B.data[j].offset);
					fprintf(file, "\t\t\tsize: 0x%08X\n", cfg->commands[i].cmd_0B.data[j].size);
					
					fprintf(file, "\t\t\tReplaceData:\n");
					write_data(file, cfg->commands[i].cmd_0B.data[j].ReplaceData, cfg->commands[i].cmd_0B.data[j].size, 0, 5);

					fprintf(file, "\t\t\tOriginalData:\n");
					write_data(file, cfg->commands[i].cmd_0B.data[j].OriginalData, cfg->commands[i].cmd_0B.data[j].size, 0, 5);
				}
				break;
			}
			case 0x0C:
			{
				fprintf(file, "\t\tparam1: 0x%04X\n", cfg->commands[i].twoU16.param1);
				fprintf(file, "\t\tparam2: 0x%04X\n", cfg->commands[i].twoU16.param2);
				break;
			}
			case 0x12:
			{
				fprintf(file, "\t\tcount: 0x%08X\n", cfg->commands[i].oneArrayU32.count);
				for (uint32_t j = 0; j < cfg->commands[i].oneArrayU32.count; j++) {
					fprintf(file, "\t\t\tparam[%u]: 0x%08X\n", j, cfg->commands[i].oneArrayU32.paramArray[j]);
				}
				break;
			}
			case 0x13: case 0x20: case 0x24:
			{
				fprintf(file, "\t\tparam: 0x%016llX\n", cfg->commands[i].oneU64.param);
				break;
			}
			case 0x42:
			{
				fprintf(file, "\t\toffset: 0x%08X\n", cfg->commands[i].cmd_42.offset);
				fprintf(file, "\t\tcount: 0x%08X\n", cfg->commands[i].cmd_42.count);
				write_data(file, (uint8_t *) &cfg->commands[i].cmd_42.param, 4*cfg->commands[i].cmd_42.count, 0, 5);
				
               
				break;
			}
			case 0x4B:
			{
				fprintf(file, "\t\toffset: 0x%08X\n", cfg->commands[i].cmd_4B.offset);
				fprintf(file, "\t\tRedirect: 0x%08X\n", cfg->commands[i].cmd_4B.Redirect);
				fprintf(file, "\t\t\tID: ");	
				if( cfg->commands[i].cmd_4B.Redirect == -1) {
					write_data(file, (uint8_t *) &cfg->commands[i].cmd_4B.data, 0x10, 0, 0);
				} else {
					fprintf(file, "%s\n", (char *) cfg->commands[i].cmd_4B.data);
				}
				break;
			}
			default:
			{
				fprintf(file, "Unknown command ID: 0x%08X\n", cfg->commands[i].cmdid);
				break;
			}
		}
	}
	
    return 0;
}

void free_NetCfg(NetCfg_t* cfg) {
	
	/*
	for (uint32_t i = 0; i < cfg->cmdCount; i++) 
	{
		if(cfg->commands[i].cmdid == 0x0B ) {
			for (uint32_t j = 0; j < cfg->commands[i].cmd_0B.count; j++) 
			{
				FREE(cfg->commands[i].cmd_0B.data[j].ReplaceData);
				FREE(cfg->commands[i].cmd_0B.data[j].OriginalData);
			}
		}
	}
	*/
    FREE(cfg->commands);
}

int NetCfg_scandir_to_txt(char* dirpath, char* logpath) {
    DIR* dir = opendir(dirpath);
    if (!dir) {
        perror("Error opening directory");
        return -1;
    }

    FILE* logfile = fopen(logpath, "w");
    if (!logfile) {
        perror("Error opening log file");
        closedir(dir);
        return -1;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
		if(!strcmp(entry->d_name, "..") || !strcmp(entry->d_name, ".")) continue;
		
        char filepath[1024];
        snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);

        NetCfg_t cfg;
        if (load_NetCfg(filepath, &cfg) != 0) {
            fprintf(stderr, "Failed to load file: %s\n", filepath);
            continue;
        }
		
		fprintf(logfile, "\n=== File: %s ===\n", entry->d_name);
        if (NetCfg_to_txt(logfile, &cfg) != 0) {
            fprintf(stderr, "Failed to write data for file: %s\n", filepath);
        }

        free_NetCfg(&cfg);
    }

    fclose(logfile);
    closedir(dir);

    return 0;
}

int netcfg_log(char *filepath, char *logpath) {
	if (!netLog) {
		netLog = fopen(logpath, "w");
		if (!netLog) {
			perror("Error opening log file");
			return -1;
		}
	}
	NetCfg_t cfg;
	if (load_NetCfg(filepath, &cfg) != 0) {
		fprintf(stderr, "Failed to load file: %s\n", filepath);
		return -1;
	}
	fprintf(netLog, "\n=== File: %s ===\n", filepath);
	if (NetCfg_to_txt(netLog, &cfg) != 0) {
		fprintf(stderr, "Failed to write data for file: %s\n", filepath);
	}
	free_NetCfg(&cfg);
	return 0;
}

int netcfg_netcfg(char *filepath, char *dirOut) {
	NetCfg_t cfg;
	if (load_NetCfg(filepath, &cfg) != 0) {
		fprintf(stderr, "Failed to load file: %s\n", filepath);
		return -1;
	}
	char outpath[1024];
	snprintf(outpath, sizeof(outpath), "%s/%s", dirOut, custom_basename(filepath));

	FILE* file = fopen(outpath, "wb");
	if (!file) {
		perror("Error opening file for writing");
		free_NetCfg(&cfg);
		return -1;
	}
	if (save_NetCfg(outpath, &cfg) != 0) {
		fprintf(stderr, "Failed to write data for file: %s\n", filepath);
		free_NetCfg(&cfg);
		fclose(file);
		return -1;
	}
	free_NetCfg(&cfg);
	fclose(file);

	unsigned char md5_filepath[MD5_DIGEST_LENGTH];
	unsigned char md5_outpath[MD5_DIGEST_LENGTH];

	if (calculate_md5(filepath, md5_filepath) != 0) {
		fprintf(stderr, "Failed to calculate MD5 for file: %s\n", filepath);
		return -1;
	}

	if (calculate_md5(outpath, md5_outpath) != 0) {
		fprintf(stderr, "Failed to calculate MD5 for file: %s\n", outpath);
		return -1;
	}

	if (memcmp(md5_filepath, md5_outpath, MD5_DIGEST_LENGTH) != 0) {
		fprintf(stderr, "MD5 mismatch between %s and %s\n", filepath, outpath);
		return -1;
	}

	return 0;
}
