#ifndef  ZCYTRIE_H
#define  ZCYTRIE_H

#include "../../elementary.h"

#include <cmath>
#include <queue>
#include <map>


using namespace std;

// 1-254
#ifdef NEXTHOP1B
typedef short zcy_nexthop_t;
#endif

#ifdef NEXTHOP2B
typedef int zcy_nexthop_t;
#endif

#ifdef NEXTHOP4B
typedef int zcy_nexthop_t;
#endif

struct ZcyTrieNode {
    ZcyTrieNode* child[2];
    nexthop_t port;
    bool solid_node;

    ZcyTrieNode* Create(nexthop_t _port, bool _solid_node);
    int CountNum();
    void Free();
    void FreeAll();
};

struct XorChunk {
    nexthop_t port;  // 8 bit
    uint32_t ip_high : 24; // 24bit
};

class ZcyTrie : public Classifier {
public:
    int Create(vector<Rule> &rules, bool insert);
    
    int InsertRule(Ip ip, uint8_t prefix_len, nexthop_t port);
    int DeleteRule(Ip ip, uint8_t prefix_len);
    // OffsetTrie24
    nexthop_t LookupV4(uint32_t ip);
    nexthop_t LookupV4_MemoryAccess(uint32_t ip, ProgramState *program_state);

    // OffsetTrie24
    nexthop_t LookupV6(Ip ip);
    nexthop_t LookupV6_MemoryAccess(Ip ip, ProgramState *program_state);
    // XorOffsetTrie
    nexthop_t LookupV6_2(Ip ip);
    nexthop_t LookupV6_2_MemoryAccess(Ip ip, ProgramState *program_state);

    uint64_t MemorySize();
    int Free();
    int Test(void *ptr);
    
    uint8_t version; // 4 or 6
	uint8_t begin_level; // 16 or 24;
    bool use_trie_port; 
    int offset_flag; // 1 offset > 0; -1 offset < 0
    bool use_xor_chunk;

private:
    void ExtendChunk(uint8_t step_index);
    void RangeSet(int level, int l, int r, nexthop_t port);
    void TrieNodePushing(ZcyTrieNode *trie_node, uint32_t layer, uint32_t location, ZcyTrieNode *pre_trie_node, uint32_t pre_layer);
    int Update(struct Ip ip, uint8_t prefix_len, nexthop_t port, int operation);

    void XorFilterChangePoint(uint64_t ip, int layer, nexthop_t port, int operation);
    void XorFilterPushing(ZcyTrieNode *trie_node, uint64_t ip, int layer, ZcyTrieNode *pre_trie_node, int pre_layer);

    uint8_t bit_num;
	uint8_t step_len;
	uint8_t level_num;

	int level_layer[129];

    ZcyTrieNode *root;
    int solid_node_num;

	int *sub_node_num[15];
	queue<int> queue_offset[15];

	uint32_t current_chunk_num[15];
	uint32_t max_chunk_num[15];

    XorChunk* xor_chunk_arr;
    char* xor_prefix_len;

    // Level 16 - 128
    // Ipv4 >=0 port, < 0 -offset
    // Ipv6 <=0 -port, > 0 offset
    zcy_nexthop_t **trie_offset;
    zcy_nexthop_t *trie_offset_8;
    zcy_nexthop_t *trie_offset_16;
    zcy_nexthop_t *trie_offset_24;
    zcy_nexthop_t *trie_offset_32;
    zcy_nexthop_t *trie_offset_40;
    zcy_nexthop_t *trie_offset_48;
    zcy_nexthop_t *trie_offset_56;
    zcy_nexthop_t *trie_offset_64;
    zcy_nexthop_t *trie_offset_72;
    zcy_nexthop_t *trie_offset_80;
    zcy_nexthop_t *trie_offset_88;
    zcy_nexthop_t *trie_offset_96;
    zcy_nexthop_t *trie_offset_104;
    zcy_nexthop_t *trie_offset_112;
    zcy_nexthop_t *trie_offset_120;
    zcy_nexthop_t *trie_offset_128;

    // for update
    ZcyTrieNode *pre_trie_nodes[129];
    uint32_t pre_trie_nodes_num;
    uint32_t update_location[16];
    uint32_t update_location_num;

};


#endif