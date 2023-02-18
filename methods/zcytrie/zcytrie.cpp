#include "zcytrie.h"

using namespace std;

ZcyTrieNode* ZcyTrieNode::Create(nexthop_t _port, bool _solid_node) {
    ZcyTrieNode* trie_node = (ZcyTrieNode*)malloc(sizeof(ZcyTrieNode));
    trie_node->child[0] = NULL;
    trie_node->child[1] = NULL;
    trie_node->port = _port;
    trie_node->solid_node = _solid_node;
    return trie_node;
}

int ZcyTrieNode::CountNum() {
    int num = 1;
    for (int i = 0; i < 2; ++i)
        if (child[i] != NULL)
            num += child[i]->CountNum();
    return num;
}

void ZcyTrieNode::Free() {
    free(this);
}

void ZcyTrieNode::FreeAll() {
    for (int i = 0; i < 2; ++i)
        if (child[i] != NULL)
            child[i]->FreeAll();
    free(this);
}

int ZcyTrie::Create(vector<Rule> &rules, bool insert) {
    if (version != 4 && version != 6) {
        printf("version should be 4 or 6\n");
        exit(1);
    }
    if (begin_level != 8 && begin_level != 16 && begin_level != 24) {
        printf("begin_level should be 8, 16 or 24\n");
        exit(1);
    }
    if (offset_flag != -1 && offset_flag != 1) {
        printf("offset_flag should be -1 or 1\n");
        exit(1);
    }

    bit_num = version == 4 ? 32 : 128;
    step_len = 8;
    level_num = (bit_num - begin_level) / step_len;  // 0 - 2 or 0 - 14

    // level_layer
    for (int i = 0; i <= bit_num; ++i)
        level_layer[i] = -1;
    for (int i = 0; i <= level_num; ++i)
        level_layer[begin_level + step_len * i] = i;
    

    if (begin_level == 8) {
        trie_offset = &trie_offset_8;
    } else if (begin_level == 16) {
        trie_offset = &trie_offset_16;
    } else if (begin_level == 24) {
        trie_offset = &trie_offset_24;
    }

    trie_offset[0] = (zcy_nexthop_t*)malloc(sizeof(zcy_nexthop_t) << begin_level);
    memset(trie_offset[0], 0, sizeof(zcy_nexthop_t) << begin_level);
    for (int i = 1; i <= level_num; ++i) {
        trie_offset[i] = NULL;
    }

    // current_chunk_num max_chunk_num
    for (int i = 0; i < level_num; ++i) {
        sub_node_num[i] = NULL;
        current_chunk_num[i] = 1;
        max_chunk_num[i] = 1;
        ExtendChunk(i);
    }
    
    root = root->Create(0, true);
    solid_node_num = 1;

    if (use_xor_chunk) {
        xor_chunk_arr = (XorChunk*)malloc(sizeof(XorChunk) << 24);
        for (int i = 0; i < (1<< 24); ++i)
            xor_chunk_arr[i].ip_high = 0xFFFFFF;
        xor_prefix_len = (char*)malloc(sizeof(char) << 24);
        memset(xor_prefix_len, 0, sizeof(char) << 24);
    }

    if (insert) {
        int rules_num = rules.size();
        for (int i = 0; i < rules_num; ++i)
            InsertRule(rules[i].ip, rules[i].prefix_len, rules[i].port);
    }
    return 0;
}

void ZcyTrie::ExtendChunk(uint8_t step_index) {
    //printf("ExtendChunk %d\n", step_index);
    max_chunk_num[step_index] <<= 1;
    int new_max_chunk_num = max_chunk_num[step_index];
    int half_max_chunk_num = max_chunk_num[step_index] >> 1;

    // trie_offset
    zcy_nexthop_t *new_trie_offset = (zcy_nexthop_t*)malloc(sizeof(zcy_nexthop_t) * new_max_chunk_num << step_len);
    memset(new_trie_offset, 0, sizeof(zcy_nexthop_t) * new_max_chunk_num << step_len);
    if (trie_offset[step_index + 1]) {
        memcpy(new_trie_offset, trie_offset[step_index + 1], sizeof(zcy_nexthop_t) * half_max_chunk_num << step_len);
        free(trie_offset[step_index + 1]);
    }
    trie_offset[step_index + 1] = new_trie_offset;

    // sub_node_num
    if (step_index < level_num) {
        int *new_sub_node_num = (int*)malloc(sizeof(int) * new_max_chunk_num);
        memset(new_sub_node_num, 0, sizeof(int) * new_max_chunk_num);
        if (sub_node_num[step_index]) {
            memcpy(new_sub_node_num, sub_node_num[step_index], sizeof(int) * half_max_chunk_num);
            free(sub_node_num[step_index]);
        }
        sub_node_num[step_index] = new_sub_node_num;
    }
}

void ZcyTrie::RangeSet(int level, int l, int r, nexthop_t port) {
    zcy_nexthop_t offset_port = -port * offset_flag;
    if (begin_level + level * step_len == bit_num)
        offset_port = port;
    for (int i = l; i <= r; ++i)
        trie_offset[level][i] = offset_port;
}

void ZcyTrie::TrieNodePushing(ZcyTrieNode *trie_node, uint32_t layer, uint32_t location, 
                              ZcyTrieNode *pre_trie_node, uint32_t pre_layer) {
    //printf("TrieNodePushing layer %d location %d\n", layer, location);
    if (trie_node->solid_node && trie_node != pre_trie_node)
        return;
    if (layer < begin_level) {
        for (int i = 0; i < 2; ++i)
            if (trie_node->child[i]) {
                TrieNodePushing(trie_node->child[i], layer + 1, location << 1 | i, pre_trie_node, pre_layer);
            } else {
                int l = (location << 1 | i) << (begin_level - layer - 1);
                int r = l + (1 << (begin_level - layer - 1)) - 1;
                RangeSet(0, l, r, pre_trie_node->port);
            }
    } else if (layer == bit_num) {
        int level = level_layer[layer];
        trie_offset[level][location] = pre_trie_node->port;
    } else if (level_layer[layer] >= 0) {
        int level = level_layer[layer];
        if (trie_offset[level][location] * offset_flag > 0) {
            uint32_t offset = trie_offset[level][location] * offset_flag;
            for (int i = 0; i < 2; ++i)
                if (trie_node->child[i]) {
                    TrieNodePushing(trie_node->child[i], layer + 1, offset << 1 | i, pre_trie_node, pre_layer);
                } else {
                    int l = (offset << 1 | i) << (step_len - 1);
                    int r = l + (1 << (step_len - 1)) - 1;
                    RangeSet(level + 1, l, r, pre_trie_node->port);
                }
        } else {
            trie_offset[level][location] = -pre_trie_node->port * offset_flag;
        }
    } else {
        for (int i = 0; i < 2; ++i)
            if (trie_node->child[i]) {
                TrieNodePushing(trie_node->child[i], layer + 1, location << 1 | i, pre_trie_node, pre_layer);
            } else {
                int bits = layer % step_len;
                int level = level_layer[layer - bits];
                int l = (location << 1 | i) << (step_len - 1 - bits);
                int r = l + (1 << (step_len - 1 - bits)) - 1;
                RangeSet(level + 1, l, r, pre_trie_node->port);
            }
    }
}

// 48位ip
void ZcyTrie::XorFilterChangePoint(uint64_t ip, int layer, nexthop_t port, int operation) {
    uint32_t ip_high = ip >> 24;
    uint32_t ip_xor = (ip & 0xFFFFFF) ^ ip_high;

    if (operation == DELETE) {
        if (xor_chunk_arr[ip_xor].ip_high == ip_high) {
            xor_prefix_len[ip_xor] = 0;
            xor_chunk_arr[ip_xor].port = 0;
            xor_chunk_arr[ip_xor].ip_high = 0xFFFFFF;
        }
    } else if (operation == INSERT) {
        if (xor_prefix_len[ip_xor] < layer) {
            xor_prefix_len[ip_xor] = layer;
            xor_chunk_arr[ip_xor].port = port;
            xor_chunk_arr[ip_xor].ip_high = ip_high;
        }
    }
}

void ZcyTrie::XorFilterPushing(ZcyTrieNode *trie_node, uint64_t ip, int layer, ZcyTrieNode *pre_trie_node, int pre_layer) {
    if (layer < 40 || layer > 48) {
        printf("Wrong XorFilterPushing\n");
        exit(1);
    }
    if (trie_node->solid_node && trie_node != pre_trie_node)
        return;
    if (layer == 48) {
        if (!trie_node->child[0] && !trie_node->child[1]) {
            uint32_t ip_high = ip >> 24;
            uint32_t ip_xor = (ip & 0xFFFFFF) ^ ip_high;

            if (xor_prefix_len[ip_xor] < pre_layer || xor_chunk_arr[ip_xor].ip_high == ip_high) {
                // 48层的增加和删除
                if (pre_layer >= 40) {
                    xor_prefix_len[ip_xor] = pre_layer;
                    xor_chunk_arr[ip_xor].port = pre_trie_node->port;
                    xor_chunk_arr[ip_xor].ip_high = ip_high;
                } else {
                    xor_prefix_len[ip_xor] = 0;
                    xor_chunk_arr[ip_xor].port = 0;
                    xor_chunk_arr[ip_xor].ip_high = 0xFFFFFF;
                }
            }
        }
    } else {
        for (int i = 0; i < 2; ++i)
            if (trie_node->child[i]) {
                XorFilterPushing(trie_node->child[i], ip << 1 | i, layer + 1, pre_trie_node, pre_layer);
            } else {
                uint64_t l = (ip << 1 | i) << (47 - layer);
                uint64_t r = l + (1 << (47 - layer)) - 1;
                uint32_t ip_high = l >> 24;

                for (int64_t j = l; j <= r; ++j) {
                    uint32_t ip_xor = (j & 0xFFFFFF) ^ ip_high;
                    // 40-47层的增加和删除
                    if (xor_prefix_len[ip_xor] < pre_layer || xor_chunk_arr[ip_xor].ip_high == ip_high) {
                        if (pre_layer >= 40) {
                            xor_prefix_len[ip_xor] = pre_layer;
                            xor_chunk_arr[ip_xor].port = pre_trie_node->port;
                            xor_chunk_arr[ip_xor].ip_high = ip_high;
                        } else {
                            xor_prefix_len[ip_xor] = 0;
                            xor_chunk_arr[ip_xor].port = 0;
                            xor_chunk_arr[ip_xor].ip_high = 0xFFFFFF;
                        }
                    }
                }
            }
    }
}

int ZcyTrie::Update(Ip ip, uint8_t prefix_len, nexthop_t port, int operation) {
    if (prefix_len == 0) {
        printf("prefix_len should not be 0\n");
        exit(1);
    }

    ZcyTrieNode *pre_trie_node = root;
    int pre_layer = 0;
    ZcyTrieNode *trie_node = root;

    pre_trie_nodes_num = 0;
    pre_trie_nodes[pre_trie_nodes_num++] = trie_node;

    uint32_t layer = 0, location = 0;
    update_location_num = 0;

    // trie
    for (layer = 0; layer < prefix_len; ++layer) {
        int bit = ip.GetBit(layer, version);
        if (trie_node->child[bit] == NULL)
            trie_node->child[bit] = trie_node->child[bit]->Create(0, false);
        trie_node = trie_node->child[bit];
        pre_trie_nodes[pre_trie_nodes_num++] = trie_node;
    }
    trie_node = root;


    for (layer = 0; layer < prefix_len; ++layer) {
        if (trie_node->solid_node) {
            pre_trie_node = trie_node;
            pre_layer = layer;
        }
        
        int bit = ip.GetBit(layer, version);
        trie_node = trie_node->child[bit];
        // offset and port
        int level = level_layer[layer];
        if (level == -1) {  
            location = location << 1 | bit;
        } else {
            update_location[update_location_num++] = location;
            //printf("layer %d level %d location %d\n", layer, level, location);
            //printf("trie_offset[level][location] %d\n", trie_offset[level][location]);
            if (trie_offset[level][location] * offset_flag <= 0) {
                if (!queue_offset[level].empty()) {
                    trie_offset[level][location] = queue_offset[level].front() * offset_flag;
                    queue_offset[level].pop();
                    //printf("queue_offset pop %d %d\n", level, trie_offset[level][location]);
                } else {
                    if (current_chunk_num[level] == max_chunk_num[level])
                        ExtendChunk(level);
                    trie_offset[level][location] = current_chunk_num[level] * offset_flag;
                }
                ++current_chunk_num[level];
                // printf("chunk\n");
                TrieNodePushing(trie_node, layer, location, pre_trie_node, pre_layer);
                if (use_xor_chunk && layer == 48)
                    XorFilterChangePoint(ip.high >> 16, 0, 0, DELETE);
            }
            location = (trie_offset[level][location] * offset_flag) << 1 | bit;
        }
    }
    if (operation == INSERT) {
        if (!trie_node->solid_node) {
            ++solid_node_num;
            for (int i = 0; i < update_location_num; ++i)
                ++sub_node_num[i][trie_offset[i][update_location[i]] * offset_flag];
        } else {
            printf("Same\n");
            exit(1);
        }

        trie_node->port = port;
        trie_node->solid_node = true;
        TrieNodePushing(trie_node, layer, location, trie_node, layer);
        if (use_xor_chunk && 40 <= layer && layer <= 48)
            XorFilterPushing(trie_node, ip.high >> (64 - layer), layer, trie_node, layer);
    } else if (operation == DELETE) {
        if (!trie_node->solid_node) {
            printf("Delete don't exit\n");
            return 1;
        }
        --solid_node_num;
        trie_node->solid_node = false;
        trie_node->port = 0;

        // update trie_offset
        int max_level = update_location_num;
        for (int i = update_location_num - 1; i >= 0; --i) {
            int offset_location = update_location[i];
            int sub_node_location = trie_offset[i][offset_location] * offset_flag;
            int now_sub_node_num = --sub_node_num[i][sub_node_location];
            if (now_sub_node_num == 0) {
                queue_offset[i].push(sub_node_location);
                trie_offset[i][offset_location] = -pre_trie_node->port * offset_flag;
                --current_chunk_num[i];
                max_level = i;
            } else if (now_sub_node_num < 0) {
                printf("error now_sub_node_num\n");
            }
        }
        
        // update offset, port, xor_chunk_arr
        if (layer <= begin_level + max_level * step_len)
            TrieNodePushing(trie_node, layer, location, pre_trie_node, pre_layer);
        if (use_xor_chunk) {
            if (layer > 48) {
                if (40 <= pre_layer && pre_layer <= 48 && begin_level + max_level * step_len <= 48)
                    XorFilterChangePoint(ip.high >> 16, pre_layer, pre_trie_node->port, INSERT);
            } else if (40 <= layer && layer <= 48) {
                XorFilterPushing(trie_node, ip.high >> (64 - layer), layer, pre_trie_node, pre_layer);
            }
        }

        // update trie
        for (int i = pre_trie_nodes_num - 1; i > 0; --i) {
            if(pre_trie_nodes[i]->child[0] == NULL && pre_trie_nodes[i]->child[1] == NULL && !pre_trie_nodes[i]->solid_node) {
                int bit = pre_trie_nodes[i] == pre_trie_nodes[i - 1]->child[0] ? 0 : 1;
                pre_trie_nodes[i - 1]->child[bit] = NULL;
                free(pre_trie_nodes[i]);
            } else {
                break;
            }
        }
    }

    return 0;
}


     
int ZcyTrie::InsertRule(Ip ip, uint8_t prefix_len, nexthop_t port) {
    return Update(ip, prefix_len, port, INSERT);
}

int ZcyTrie::DeleteRule(Ip ip, uint8_t prefix_len) {
    return Update(ip, prefix_len, 0, DELETE);
}


// OffsetTrie24 offset_flag = -1
nexthop_t ZcyTrie::LookupV4(uint32_t ip) {
    zcy_nexthop_t offset = trie_offset_24[ip >> 8];;
    if (offset >= 0)
        return offset;
    return trie_offset_32[(-offset) << 8 | (ip & 255)];
}

nexthop_t ZcyTrie::LookupV4_MemoryAccess(uint32_t ip, ProgramState *program_state) {
    program_state->memory_access.AddNum();
    zcy_nexthop_t offset = trie_offset_24[ip >> 8];;
    program_state->cache_access[(uint64_t)&trie_offset_24[ip >> 8] / 64]++;
    if (offset >= 0)
        return offset;
    program_state->memory_access.AddNum();
    return trie_offset_32[(-offset) << 8 | (ip & 255)];
}

// OffsetTrie24
nexthop_t ZcyTrie::LookupV6(Ip ip) {
    zcy_nexthop_t offset = trie_offset_24[ip.high >> 40];

    if (offset <= 0)
        return -offset;

    if ((offset = trie_offset_32[(offset << 8) | (ip.high >> 32 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_40[(offset << 8) | (ip.high >> 24 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_48[(offset << 8) | (ip.high >> 16 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_56[(offset << 8) | (ip.high >> 8 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_64[(offset << 8) | (ip.high & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_72[(offset << 8) | (ip.low >> 56 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_80[(offset << 8) | (ip.low >> 48 & 255)]) <= 0)
        return -offset;
    
    if ((offset = trie_offset_88[(offset << 8) | (ip.low >> 40 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_96[(offset << 8) | (ip.low >> 32 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_104[(offset << 8) | (ip.low >> 24 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_112[(offset << 8) | (ip.low >> 16 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_120[(offset << 8) | (ip.low >> 8 & 255)]) <= 0)
        return -offset;

    return trie_offset_128[(offset << 8) | (ip.low & 255)];
}

nexthop_t ZcyTrie::LookupV6_MemoryAccess(Ip ip, ProgramState *program_state) {
    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_24[ip.high >> 40] / 64]++;
    zcy_nexthop_t offset = trie_offset_24[ip.high >> 40];

    if (offset <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_32[(offset << 8) | (ip.high >> 32 & 255)] / 64]++;
    if ((offset = trie_offset_32[(offset << 8) | (ip.high >> 32 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_40[(offset << 8) | (ip.high >> 24 & 255)] / 64]++;
    if ((offset = trie_offset_40[(offset << 8) | (ip.high >> 24 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_48[(offset << 8) | (ip.high >> 16 & 255)] / 64]++;
    if ((offset = trie_offset_48[(offset << 8) | (ip.high >> 16 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_56[(offset << 8) | (ip.high >> 8 & 255)] / 64]++;
    if ((offset = trie_offset_56[(offset << 8) | (ip.high >> 8 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_64[(offset << 8) | (ip.high & 255)] / 64]++;
    if ((offset = trie_offset_64[(offset << 8) | (ip.high & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_72[(offset << 8) | (ip.low >> 56 & 255)] / 64]++;
    if ((offset = trie_offset_72[(offset << 8) | (ip.low >> 56 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_80[(offset << 8) | (ip.low >> 48 & 255)] / 64]++;
    if ((offset = trie_offset_80[(offset << 8) | (ip.low >> 48 & 255)]) <= 0)
        return -offset;
    
    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_88[(offset << 8) | (ip.low >> 40 & 255)] / 64]++;
    if ((offset = trie_offset_88[(offset << 8) | (ip.low >> 40 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_96[(offset << 8) | (ip.low >> 32 & 255)] / 64]++;
    if ((offset = trie_offset_96[(offset << 8) | (ip.low >> 32 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_104[(offset << 8) | (ip.low >> 24 & 255)] / 64]++;
    if ((offset = trie_offset_104[(offset << 8) | (ip.low >> 24 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_112[(offset << 8) | (ip.low >> 16 & 255)] / 64]++;
    if ((offset = trie_offset_112[(offset << 8) | (ip.low >> 16 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_120[(offset << 8) | (ip.low >> 8 & 255)] / 64]++;
    if ((offset = trie_offset_120[(offset << 8) | (ip.low >> 8 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_128[(offset << 8) | (ip.low & 255)] / 64]++;
    return trie_offset_128[(offset << 8) | (ip.low & 255)];
}


// XorFilter
nexthop_t ZcyTrie::LookupV6_2(Ip ip) {

    uint32_t ip_high = ip.high >> 40;

    uint32_t ip_xor = (ip.high >> 16 & 0xFFFFFF) ^ ip_high;

    // XorFilter
    if (xor_chunk_arr[ip_xor].ip_high == ip_high) {
        // printf("lookup XorFilter %d \n", xor_chunk_arr[ip_xor].port);
        return xor_chunk_arr[ip_xor].port;
    }
    
    // OffsetTrie24
    zcy_nexthop_t offset = trie_offset_24[ip_high];

    if (offset <= 0)
        return -offset;

    if ((offset = trie_offset_32[(offset << 8) | (ip.high >> 32 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_40[(offset << 8) | (ip.high >> 24 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_48[(offset << 8) | (ip.high >> 16 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_56[(offset << 8) | (ip.high >> 8 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_64[(offset << 8) | (ip.high & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_72[(offset << 8) | (ip.low >> 56 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_80[(offset << 8) | (ip.low >> 48 & 255)]) <= 0)
        return -offset;
    
    if ((offset = trie_offset_88[(offset << 8) | (ip.low >> 40 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_96[(offset << 8) | (ip.low >> 32 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_104[(offset << 8) | (ip.low >> 24 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_112[(offset << 8) | (ip.low >> 16 & 255)]) <= 0)
        return -offset;

    if ((offset = trie_offset_120[(offset << 8) | (ip.low >> 8 & 255)]) <= 0)
        return -offset;

    return trie_offset_128[(offset << 8) | (ip.low & 255)];
}

nexthop_t ZcyTrie::LookupV6_2_MemoryAccess(Ip ip, ProgramState *program_state) {

    uint32_t ip_high = ip.high >> 40;

    uint32_t ip_xor = (ip.high >> 16 & 0xFFFFFF) ^ ip_high;

    // XorFilter
    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&xor_chunk_arr[ip_xor] / 64]++;
    if (xor_chunk_arr[ip_xor].ip_high == ip_high)
        return xor_chunk_arr[ip_xor].port;

    // OffsetTrie24
    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_24[ip_high] / 64]++;
    zcy_nexthop_t offset = trie_offset_24[ip_high];

    if (offset <= 0)
        return -offset;
    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_32[(offset << 8) | (ip.high >> 32 & 255)] / 64]++;
    if ((offset = trie_offset_32[(offset << 8) | (ip.high >> 32 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_40[(offset << 8) | (ip.high >> 24 & 255)] / 64]++;
    if ((offset = trie_offset_40[(offset << 8) | (ip.high >> 24 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_48[(offset << 8) | (ip.high >> 16 & 255)] / 64]++;
    if ((offset = trie_offset_48[(offset << 8) | (ip.high >> 16 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_56[(offset << 8) | (ip.high >> 8 & 255)] / 64]++;
    if ((offset = trie_offset_56[(offset << 8) | (ip.high >> 8 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_64[(offset << 8) | (ip.high & 255)] / 64]++;
    if ((offset = trie_offset_64[(offset << 8) | (ip.high & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_72[(offset << 8) | (ip.low >> 56 & 255)] / 64]++;
    if ((offset = trie_offset_72[(offset << 8) | (ip.low >> 56 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_80[(offset << 8) | (ip.low >> 48 & 255)] / 64]++;
    if ((offset = trie_offset_80[(offset << 8) | (ip.low >> 48 & 255)]) <= 0)
        return -offset;
    
    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_88[(offset << 8) | (ip.low >> 40 & 255)] / 64]++;
    if ((offset = trie_offset_88[(offset << 8) | (ip.low >> 40 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_96[(offset << 8) | (ip.low >> 32 & 255)] / 64]++;
    if ((offset = trie_offset_96[(offset << 8) | (ip.low >> 32 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_104[(offset << 8) | (ip.low >> 24 & 255)] / 64]++;
    if ((offset = trie_offset_104[(offset << 8) | (ip.low >> 24 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_112[(offset << 8) | (ip.low >> 16 & 255)] / 64]++;
    if ((offset = trie_offset_112[(offset << 8) | (ip.low >> 16 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_120[(offset << 8) | (ip.low >> 8 & 255)] / 64]++;
    if ((offset = trie_offset_120[(offset << 8) | (ip.low >> 8 & 255)]) <= 0)
        return -offset;

    program_state->memory_access.AddNum();
    program_state->cache_access[(uint64_t)&trie_offset_128[(offset << 8) | (ip.low & 255)] / 64]++;
    return trie_offset_128[(offset << 8) | (ip.low & 255)];
}


uint64_t ZcyTrie::MemorySize() {
    uint64_t memory_size = sizeof(ZcyTrie);
    memory_size += root->CountNum() * sizeof(ZcyTrieNode);

    uint64_t chunk_num = 0;
    for (int i = 0; i < level_num; ++i)
        chunk_num += current_chunk_num[i];
    memory_size += chunk_num * sizeof(int);

    uint64_t arr_num = (1 << begin_level) + (chunk_num << 8);
    
    memory_size += arr_num * sizeof(zcy_nexthop_t);

    if (use_xor_chunk) {
        memory_size += (1 << 24) * (sizeof(XorChunk) + sizeof(char));
    }
    return memory_size;
}

int ZcyTrie::Free() {
    if (root != NULL)
        root->FreeAll();
    for (int i = 0; i < level_num; ++i)
        free(sub_node_num[i]);
    for (int i = 0; i <= level_num; ++i) {
        free(trie_offset[i]);
    }
    if (use_xor_chunk) {
        free(xor_chunk_arr);
        free(xor_prefix_len);
    }
    return 0;
}

int ZcyTrie::Test(void *ptr) {
    return 0;
}