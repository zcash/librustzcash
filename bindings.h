#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <new>

template<typename T>
struct Option;

struct NodeLink {
  enum class Tag {
    Stored,
    Generated,
  };

  struct Stored_Body {
    uint32_t _0;
  };

  struct Generated_Body {
    uint32_t _0;
  };

  Tag tag;
  union {
    Stored_Body stored;
    Generated_Body generated;
  };
};

struct NodeData {
  uint8_t subtree_commitment[32];
  uint32_t start_time;
  uint32_t end_time;
  uint32_t start_target;
  uint32_t end_target;
  uint8_t start_sapling_root[32];
  uint8_t end_sapling_root[32];
  uint64_t subtree_total_work;
  uint32_t start_height;
  uint32_t end_height;
  uint64_t shielded_tx;
};

struct MMRNode {
  Option<NodeLink> left;
  Option<NodeLink> right;
  NodeData data;
};

extern "C" {

void append(const MMRNode *stored,
            uint32_t stored_count,
            const MMRNode *generated,
            uint32_t generated_count,
            uint32_t *append_count,
            MMRNode *append_buffer);

} // extern "C"
