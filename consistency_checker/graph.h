/*
 * Base graph class
 *
 */
#ifndef _CCHECKER_GRAPH_H_
#define _CCHECKER_GRAPH_H_

#include <unordered_map>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <cassert>
#include <queue>
#include <set>
#include <map>

using namespace std;

namespace cchecker_graph {

        template<typename V>
        class Graph {
        public:

                size_t num_vertices(void) const noexcept {
                        return _vertices.size();
                }

                void add_vertex(const V& v) {
                        _vertices.push_back(v);
                }

                void remove_vertex(const V& v) {
                        auto &it = std::find(_vertices.begin(), _vertices.end(), v);
                        if (it != _vertices.end())
                                _vertices.erase(it);
                }

                void add_edge(const V &from, const V &to) {
                        _adjlist.add_edge(from, to);
                }

                void delete_edge(const V &from, const V &to) {
                        _adjlist.delete_edge(from, to);
                }

                void print_edges(void) {
                        _adjlist.print_edges();
                }

                class NodeIterator {
                        public:
                                NodeIterator(Graph<V> &g) {
                                        if (!g._vertices.empty()) {
                                                start_iter = g._vertices.begin();
                                                end_iter   = g._vertices.end();
                                        } else {
                                                start_iter = end_iter;
                                        }
                                }

                                ~NodeIterator(void) {
                                }

                                bool valid(void) {
                                        return (start_iter != end_iter);
                                }

                                NodeIterator& operator++() {
                                        start_iter++;
                                        return *this;
                                }

                                NodeIterator operator++(int) {
                                        NodeIterator temp = *this;
                                        start_iter++;
                                        return temp;
                                }

                                const V& operator*() {
                                        return *start_iter;
                                }

                                NodeIterator operator--() {
                                        start_iter--;
                                        return *this;
                                }

                        private:
                
                                typename std::vector<V>::iterator start_iter;
                                typename std::vector<V>::iterator end_iter;
                };

                class AdjacencyList {
                        public:
                                AdjacencyList() {}

                                ~AdjacencyList() {
                                        clear_edges();
                                }

                                void add_edge(const V &from, const V &to) {
                                        if (_edges.find(from) == _edges.end())
                                                _edges[from] = std::set<V>();
                                        _edges[from].insert(to);
                                }

                                void delete_edge(const V &from, const V &to) {
                                        if (_edges.find(from) == _edges.end())
                                                return;
                                        auto &neighbours = _edges[from];
                                        auto &iter = neighbours.find(to);
                                        if (iter == neighbours.end())
                                                return;
                                        neighbours.erase(iter);
                                }

                                void clear_edges(void) {
                                        if (!_edges.size())
                                                return;
                                        for (auto it = _edges.begin(); it != _edges.end(); it++)
                                                (*it).second.clear();
                                        _edges.clear();
                                }

                                void print_edges(void) {
                                        std::cout << "==adjacency list==" << std::endl;
                                        for (auto &e : _edges) {
                                                cout << e.first << "[" << e.second.size() << "] :";
                                                for (auto &v : e.second)
                                                        cout << v << " ";
                                                cout << endl;
                                        }
                                }

                                class EdgeIterator {
                                        public:
                                                EdgeIterator(AdjacencyList &adjlist, const V &start) {
                                                        if (adjlist._edges.find(start) != adjlist._edges.end()) {
                                                                start_iter = adjlist._edges[start].begin();
                                                                end_iter = adjlist._edges[start].end();
                                                        } else {
                                                                std::cerr << "vertex has no edge : " << start << std::endl;
                                                                start_iter = end_iter;
                                                                //throw std::runtime_error("invalid vertex");
                                                        }
                                                }

                                                ~EdgeIterator(void) {
                                                }

                                                bool valid(void) {
                                                        return (start_iter != end_iter);
                                                }

                                                EdgeIterator& operator ++() {
                                                        start_iter++;
                                                        return *this;
                                                }

                                                EdgeIterator operator ++(int) {
                                                        EdgeIterator temp = *this;
                                                        start_iter++;
                                                        return temp;
                                                }

                                                const V& operator*() {
                                                        return *start_iter;
                                                }

                                                EdgeIterator operator--() {
                                                        start_iter--;
                                                        return *this;
                                                }

                                        private:
                                                        typename std::set<V>::iterator start_iter;
                                                        typename std::set<V>::iterator end_iter;
                                };

                        private:
                                std::unordered_map<V, std::set<V>> _edges;
                };

                AdjacencyList &get_adjacency_list(void) {
                        return _adjlist;
                }

        private:

                std::vector<V> _vertices;

                AdjacencyList _adjlist;
        };

        typedef enum Color {
                WHITE,
                GRAY,
                BLACK,
        } Color;

        //
        // have a dependant name, that is, a name that depends on a template
        // parameter
        //
        template<typename V>
        bool Print(Graph<V> &graph) {
                typename Graph<V>::AdjacencyList &adjlist = graph.get_adjacency_list();
                std::cout << "===graph nodes===" << std::endl;
                for (typename Graph<V>::NodeIterator node_iter(graph); node_iter.valid(); node_iter++) {
                        std::cout << "vertex : " << *node_iter << std::endl;
                        for(typename Graph<V>::AdjacencyList::EdgeIterator edge_iter(adjlist, *node_iter);
                                        edge_iter.valid(); edge_iter++)
                                std::cout << "edge : " << *node_iter << "->" << *edge_iter << std::endl;
                }
                return true;
        }

        template<typename V>
        bool DetectCycle(Graph<V> &graph) {
                std::queue<V> queue;
                std::map<V, Color> color_map;
                typename Graph<V>::AdjacencyList &adjlist = graph.get_adjacency_list();

                // initialize vertices
                for (typename Graph<V>::NodeIterator node_iter(graph); node_iter.valid(); node_iter++)
                        color_map[*node_iter] = WHITE;

                // start vertex
                for (typename Graph<V>::NodeIterator node_iter(graph); node_iter.valid(); node_iter++) {
                        if (color_map[*node_iter] != WHITE)
                                continue;
                        //discover vertex
                        queue.push(*node_iter);
                        color_map[*node_iter] = BLACK;

                        while (!queue.empty()) {
                                V v = queue.front();
                                queue.pop();

                                // examine edge
                                for(typename Graph<V>::AdjacencyList::EdgeIterator edge_iter(adjlist, v);
                                        edge_iter.valid(); edge_iter++) {
                                        if (color_map[*edge_iter] != WHITE) {
                                                std::cout << "cycle :" << v << "<>" << *edge_iter << std::endl;
                                                return true;
                                        }
                                        color_map[*edge_iter] = BLACK;
                                        queue.push(*edge_iter);
                                }
                        }
                }
                return false;
        }
};
#endif
