// From https://gist.github.com/wwylele/0bc1ca527fa54ecfb4c5bf2e78a6c2a5

#ifndef BIT_TRIE_H
#define BIT_TRIE_H

#include <algorithm>
#include <climits>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

/*
bit_trie
  bit_tries are associative containers that store elements formed
  by the combination of a key value and a mapped value, and which
  allows for fast retrieval of individual elements based on their keys.
 Key
  Type of the key values. Each element in an bit_tire is uniquely
  identified by its key value.
 Value
  Type of the mapped values.
 BitTester
  A binary function object type that takes an object of type Key
  and a size_t integer (bit address) as arguments and returns a bool.
  The bit address is an integer less than bit length. The function
  should return a consistent result for the same key and the same
  bit address. The results for two differents key should be different
  for at least one bit address.
*/
template <
    typename Key,
    typename Value,
    typename BitTester
>
class bit_trie {
    struct Branch{
        int offset;
        bool end;
    };
    struct Node {
        std::size_t bit_address;
        Branch left;
        Branch right;
        Key key; // this can be removed if use only at_no_verify to retrieve elements
        Value value;
    };

    BitTester tester;
    Node& at_node(const Key& key) {
        size_t cur_pos = 0;
        Branch next = nodes[0].left;
        while (true) {
            cur_pos += next.offset;
            if (next.end)
                return nodes[cur_pos];
            if (tester(key, nodes[cur_pos].bit_address)) {
                next = nodes[cur_pos].right;
            } else {
                next = nodes[cur_pos].left;
            }
        }
    }
    void build(typename std::vector<Node>::iterator begin, typename std::vector<Node>::iterator end, std::size_t bit_length) {
        // counting number of elements and numbers passing each bit test
        std::vector<std::size_t> pass_count(bit_length);
        std::size_t count = 0;
        std::for_each(begin, end, [&](const Node& node){
            for (std::size_t bit = 0; bit < bit_length; ++bit) {
                if (tester(node.key, bit))
                    ++pass_count[bit];
            }
            ++count;
        });
        if (count == 1)
            return;

        // find the best address that partition the elements evenly
        long badness = LONG_MAX;
        std::size_t best_address;
        for (std::size_t address = 0; address < bit_length; ++ address) {
            long current = std::abs((long)(pass_count[address] - count / 2));
            if (current < badness) {
                badness = current;
                best_address = address;
            }
        }

        // partition
        auto partition_pos = std::partition(begin, end, [&](const Node& node){
            return !tester(node.key, best_address);
        });
        auto partition_distance = std::distance(begin, partition_pos);
        if (partition_distance == count || partition_distance == 0)
            throw std::invalid_argument("Duplicated keys.");

        // build trie for each partition
        build(begin, partition_pos, bit_length);
        build(partition_pos, end, bit_length);

        // let right guiding node be the first level node
        partition_pos->right = partition_pos->left;
        partition_pos->left = begin->left;
        partition_pos->left.offset -= partition_distance;
        partition_pos->bit_address = best_address;
        // and left guiding node be the main guiding node
        begin->left.offset = partition_distance;
        begin->left.end = false;
    }
public:
    std::vector<Node> nodes;
    template <typename InputInterator>
    bit_trie(
        InputInterator begin,
        InputInterator end,
        std::size_t bit_length,
        const BitTester& tester_ = BitTester()
    ) : nodes(std::distance(begin, end)), tester(tester_) {
        constexpr std::size_t invalid_bit_address = static_cast<std::size_t>(-1);
        std::transform(begin, end, nodes.begin(), [](std::pair<Key, Value> pair){
            return Node {
                invalid_bit_address,
                {0, true},
                {0, true},
                pair.first,
                pair.second
            };
        });
        if (nodes.empty())
            throw std::length_error("Empty range.");

        build(nodes.begin(), nodes.end(), bit_length);
    }

    Value& at(const Key& key) {
        Node& node = at_node(key);
        if (node.key == key)
            return node.value;
        throw std::out_of_range("Element not found.");
    }

    Value& at_no_verify(const Key& key) {
        return at_node(key).value;
    }

};

bool string_tester(const std::string& key, std::size_t position) {
    std::size_t byte = position >> 3;
    if (byte >= key.size())
        return false;
    return (key[byte] >> (position & 7)) & 1;
}

#endif
