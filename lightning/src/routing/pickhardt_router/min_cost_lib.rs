#![allow(missing_docs)]
// TODO: add back 0 cost edges for negative cycle, make it work (now buggy :( ))
// min_cost alternative Rust implementation
// Usage: cargo run  --bin min_cost_rs --release

#[derive(Clone)]
pub struct OriginalEdge {
	pub u: usize,
	pub v: usize,
	pub capacity: i32,
	pub cost: i32,
	pub flow: i32,
	pub guaranteed_liquidity: i32
}

use std::{time::{Instant, Duration}, collections::VecDeque};

pub fn elapsed(s:&str, start : Instant) {
	println!("Time difference for  {} = {:?}", s, start.elapsed());
}

fn crc(a:i32, b:i32) -> i32 {  // Used for comparing implementations
	(a .wrapping_mul(17)) ^ (b.wrapping_mul(3))
}


#[derive(PartialEq, PartialOrd, Clone, Copy)]
struct Vindex {
	value: i32
}

impl std::fmt::Display for Vindex {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		self.value.fmt(f)
	}
}

trait Lenv {
	fn lenv(&self)->Vindex;
}

impl<T> Lenv for  Vec<T> {
	fn lenv(&self)->Vindex {
		Vindex::from_usize(self.len())
	}
}

// https://www.geeksforgeeks.org/dinics-algorithm-maximum-flow/
// C++ implementation of Dinic's Algorithm for Maximum Flow
 
// A structure to represent a edge between
// two vertex
#[derive(Clone)]
struct MaxFlowEdge {
	v:Vindex, // Vertex v (or "to" vertex)
		   // of a directed edge u-v. "From"
		   // vertex u can be obtained using
		   // index in adjacent array.
 
	flow: i32, // flow of data in edge
 
	C: i32, // capacity
 
	rev: Vindex, // To store index of reverse
			 // edge in adjacency list so that
			 // we can quickly find it.
}

impl Vindex {
	pub fn new(value: i32) -> Self {
		Self { value }
	}
	pub fn from_usize(value: usize) -> Self {
		Self { value: value as i32 }
	}
	fn as_usize(&self) -> usize {
		self.value as usize
	}
}

use core::ops::{Index, IndexMut};

impl<T> Index<Vindex> for Vec<T> {
	type Output = T;
	#[inline]
	fn index(&self, index: Vindex) -> &T {
		self.index(index.value as usize)
	}
}

impl<T> IndexMut<Vindex> for Vec<T> {
	#[inline]
	fn index_mut(&mut self, index: Vindex) -> &mut T {
		self.index_mut(index.value as usize)
	}
}
 
use std::cmp::min;

// Residual MaxFlowGraph
struct MaxFlowGraph {
	V: Vindex, // number of vertex
	level: Vec<i32>, // stores level of a node
	adj: Vec<Vec<MaxFlowEdge>>,
}

 impl MaxFlowGraph {
	fn new(N: Vindex)->Self {
		let mut r= Self { V: N, level: vec![0; N.as_usize()], adj: Vec::new() };
		for i in 0..N.as_usize() {
			r.adj.push(Vec::new())
		}
		return r
	}
	// add edge to the graph
	fn addEdge(&mut self, u: Vindex, v: Vindex, C: i32) -> Vindex
	{
		// Forward edge : 0 flow and C capacity
		let a =MaxFlowEdge  { v:v, flow:0, C: C, rev: Vindex::from_usize(self.adj[v].len())};
 
		// Back edge : 0 flow and 0 capacity
		let b = MaxFlowEdge  { v:u, flow:0, C: 0, rev: Vindex::from_usize(self.adj[u].len())};
 
		self.adj[u].push(a);
		// self.adj[u as usize].push_back(a);
		self.adj[v].push(b); // reverse edge
		return Vindex::from_usize(self.adj[u].len()-1);
	}
	
	// Finds if more flow can be sent from s to t.
	// Also assigns levels to nodes.
	fn BFS(&mut self,  s:Vindex, t:Vindex) -> bool
	{
		for  i in &mut self.level {
			*i=-1;
		}
	
		self.level[s] = 0; // Level of source vertex
	
		// Create a queue, enqueue source vertex
		// and mark source vertex as visited here
		// level[] array works as visited array also.
		let mut q: VecDeque<Vindex>=VecDeque::new();
		q.push_back(s);
		
		while !q.is_empty() {
			let u = *q.front().unwrap();
			q.pop_front();
			for e in  &self.adj[u]  {
				if self.level[e.v] < 0 && e.flow < e.C {
					// Level of current vertex is,
					// level of parent + 1
					self.level[e.v] = self.level[u] + 1;
					q.push_back(e.v);
				}
			}
		}
	
		// IF we can not reach to the sink we
		// return false else true
		return self.level[t] >= 0;
	}
	
	// A DFS based function to send flow after BFS has
	// figured out that there is a possible flow and
	// constructed levels. This function called multiple
	// times for a single call of BFS.
	// flow : Current flow send by parent function call
	// start[] : To keep track of next edge to be explored.
	//           start[i] stores  count of edges explored
	//           from i.
	//  u : Current vertex
	//  t : Sink
	fn sendFlow(&mut self, u:Vindex,  flow: i32,  t: Vindex,  start:&mut Vec<i32>)->i32
	{
		// Sink reached
		if u == t {
			return flow;
		}
	
		// Traverse all adjacent edges one -by - one.
		while start[u] < self.adj[u].len() as i32 {
			// Pick next edge from adjacency list of u
			let e = self.adj[u][start[u] as usize].clone();
	
			if self.level[e.v] == self.level[u] + 1 && e.flow < e.C {
				// find minimum flow from u to t
				let curr_flow = min(flow, e.C - e.flow);
	
				let temp_flow
					= self.sendFlow(e.v, curr_flow, t, start);
	
				// flow is greater than zero
				if temp_flow > 0 {
					// add flow  to current edge
					self.adj[u][start[u] as usize].flow += temp_flow;
	
					// subtract flow from reverse edge
					// of current edge
					self.adj[e.v][e.rev].flow -= temp_flow;
					return temp_flow;
				}
			}
			start[u]+=1;
		}
	
		return 0;
	}
	
	// Returns maximum flow in graph
	fn  DinicMaxflow(&mut self, s: Vindex, t: Vindex, limit: i32) ->i32
	{
		// Corner case
		if s == t {
			return -1;
		}
	
		let mut total = 0; // Initialize result
	
		// Augment the flow while there is path
		// from source to sink
		while total < limit && self.BFS(s, t) == true {
			// store how many edges are visited
			// from V { 0 to V }
			let mut start=vec![0; (self.V.value+1) as usize];
			let mut flow = self.sendFlow(s, limit-total, t, &mut start);
	
			// while flow is not zero in graph from S to D
			while flow > 0 {
				// Add path flow to overall flow
				total += flow;
				flow = self.sendFlow(s, limit-total, t, &mut start)
			}
		}
	
		// return maximum flow
		return total;
	}

}


// Using the Shortest Path Faster Algorithm to find a negative cycle
// https://konaeakira.github.io/posts/using-the-shortest-path-faster-algorithm-to-find-negative-cycles.html

#[inline]
fn detect_cycle( n:Vindex, pre:&Vec<Vindex>) -> Vec<Vindex>
{
	let mut visited=vec![false; n.as_usize()];
	let mut on_stack=vec![false; n.as_usize()];
	let mut vec: Vec<Vindex>=Vec::new();
	for i in 0..n.as_usize() {
		if !visited[i]
		{
			let mut j=Vindex::from_usize(i);
			while j.value != -1 {
				if !visited[j]
				{
					visited[j] = true;
					vec.push(j);
					on_stack[j] = true;
				}
				else
				{
					if on_stack[j] {
						let mut jj=0;
						while vec[jj]!=j {
							jj+=1;
						}
						let mut vec2 =vec[jj..].to_vec();
						vec2.reverse();
						return vec2;
					}
					break;
				}
				j = pre[j]
			}
			for  j in &vec {
				on_stack[*j] = false;
			}
			vec.clear();
		}
	}
	return vec;
}

#[inline]
fn update_dis(u:Vindex, v:Vindex, w:i32, disu:i64, pre:&mut Vec<Vindex>, dis:&mut Vec<i64>,
	in_queue:&mut Vec<bool>,
	queue:&mut VecDeque<Vindex>, iter:&mut i32, n: Vindex) -> Vec<Vindex> {
				pre[v] = u;
				dis[v] = disu + w as i64;
				*iter+=1;
				if *iter == n.value
				{
					*iter = 0;
					let cycle=detect_cycle(n, pre);
					if !cycle.is_empty() {
						return cycle;
					}
				}
				if !in_queue[v]
				{
					queue.push_back(v);
					in_queue[v] = true;
				}
				return Vec::new();
	}

fn spfa_early_terminate(n: Vindex, adj:&Vec<Vec<(Vindex, i32)>>, adj2: &Vec<Vec<MinCostEdge>>) ->Vec<Vindex>
{
	let mut pre=vec![Vindex::new(-1); n.as_usize()];
	let mut dis: Vec<i64>= vec![0; n.as_usize()];
	let mut in_queue= vec![true; n.as_usize()];
	let mut queue: VecDeque<Vindex>=VecDeque::new();
	for i in 0..n.as_usize() {
		queue.push_back(Vindex::from_usize(i));
	}
	let mut iter = 0;

	while !queue.is_empty()
	{
		let u = *queue.front().unwrap();
		queue.pop_front();
		in_queue[u] = false;
		let disu: i64=dis[u];
		// cout << adj[u].len() << endl;
		
		for i in 0..adj[u].len() {
			let (v, w) : (Vindex, i32)=adj[u][i];
			let disv: i64=dis[v];
			if pre[u]==v  {  // Don't allow cycles of 2.
				continue;
			}
			if (disu + w as i64) < disv
			{
				let cycle=update_dis(u, v, w, disu,  &mut pre, &mut dis, &mut in_queue, &mut queue, &mut iter, n);
				if !cycle.is_empty() { return cycle;}
			}
		}
	}
	return detect_cycle(n, &pre);
}

fn total_cost(lightning_data : &Vec<OriginalEdge>) -> i64 {
	let mut r:i64=0;
	for i in 0..lightning_data.len() {
		let edge=&lightning_data[i];
		r+=(edge.cost as i64)*(edge.flow as i64);
		if edge.cost < 0 {
			println!("negative cost!!!!!!");
		}
		if edge.flow < 0 {
			println!("negative flow!!!!!!");
		}

		if edge.flow > edge.capacity {
			println!("overflow!!!!!!");
		}
	}
	return r;
}

#[derive(Clone)]
struct MinCostEdge {
	v: Vindex,
	remaining_capacity: i32,
	cost: i32,
	reverse_idx: Vindex,
	guaranteed_liquidity: i32,
}
fn adj_total_cost(N:Vindex, adj2 : &Vec<Vec<MinCostEdge>>)  -> i64 {
	let mut total:i64=0;
	for edges in adj2 {
		for e in edges {
			if e.cost < 0 {
				total-=e.cost as i64*e.remaining_capacity as i64;
			}
		}
	}
	return total;
}

const use_guaranteed_capacity:bool=true;

// Returns positive number
fn minus_log_probability(e:&MinCostEdge , er: &MinCostEdge) -> f32 {
	let from_total=if e.cost>0 { e.remaining_capacity } else { er.remaining_capacity };
	let capacity=e.remaining_capacity+er.remaining_capacity;
	if use_guaranteed_capacity && from_total+e.guaranteed_liquidity>=capacity {
		return 0.0;
	}
	let p=((from_total+1) as f32)/(capacity-e.guaranteed_liquidity+1) as f32;
	return -p.log2()
}

fn adj_total_mlog_prob(N : Vindex, adj2 : &Vec<Vec<MinCostEdge>>) -> f32 {
	let mut mlogp: f32=0.0;
	for edges in adj2 {
		for e in edges {
			if e.cost < 0 {
				let er=&adj2[e.v][e.reverse_idx];
				mlogp+=minus_log_probability(&e, er) as f32;
			}
		}
	}
	return mlogp;
}
// Returns 1/(from_total+1)/log(2), the derivative of minus log probability
fn dminus_log_probability(e: &MinCostEdge, er: &MinCostEdge) -> f32 {
	const  log2inv : f32=1.4426950408889634; // 1.0/(2.0_f32.ln());
	let from_total=if e.cost>0 { e.remaining_capacity } else { er.remaining_capacity };
	let capacity=e.remaining_capacity+er.remaining_capacity;
	if use_guaranteed_capacity && from_total+e.guaranteed_liquidity>=capacity {
		return 0.0;
	}
	return 1.0/from_total as f32/log2inv;
}

fn getAdj(e: &MinCostEdge, er: &MinCostEdge,  log_probability_cost_multiplier : f32) -> (Vindex, i32) {
	if e.remaining_capacity==0 {
		return (e.v, i32::MAX/2);
	}
	let mut cost: i64 = e.cost as i64;
	if log_probability_cost_multiplier >= 0.0 {
		let mut e2 : MinCostEdge =e.clone();
		let mut er2: MinCostEdge=er.clone();
		e2.remaining_capacity-=1;
		er2.remaining_capacity+=1;

		cost+=(log_probability_cost_multiplier*(minus_log_probability(&e2, &er2))).round() as i64;
		cost-=(log_probability_cost_multiplier*(minus_log_probability(&e, &er))).round() as i64;
	}
	// println!("getadj returning {} {}", e.v, cost);
	if cost > (i32::MAX/2) as i64 {
		println!("Too big cost in getAdj!!!!!!!");
		cost=(i32::MAX/2) as i64;
	}
	return (e.v, cost as i32);
}

fn relative_cost_at(at:i32, edges :& Vec<(MinCostEdge,MinCostEdge)> ,  log_probability_cost_multiplier:f32) -> i64 {
		let mut r:i64=0;
		for i in 0..edges.len() {
			let e =&edges[i].0;
			let er  =&edges[i].1;
			r+=(e.cost as i64)*at as i64;
			let mut e2:MinCostEdge=e.clone();
			let mut er2:MinCostEdge=er.clone();
			e2.remaining_capacity-=at;
			er2.remaining_capacity+=at;
			r+=(log_probability_cost_multiplier*(minus_log_probability(&e2, &er2))).round() as i64;
			r-=(log_probability_cost_multiplier*(minus_log_probability(&e, &er))).round() as i64;
		}
		return r;
}

const debug:bool=false;

fn derivative_at(at:i32,edges:& Vec<(MinCostEdge,MinCostEdge)>,  log_probability_cost_multiplier: f32) -> i64 {
	let mut r : i64=0;
	const debug: bool=false;
	if debug {
		println!("at: {at}");
	}
	for i in 0..edges.len() {
		let mut e=edges[i].0.clone();
		let mut er=edges[i].1.clone();
		e.remaining_capacity-=at;
		er.remaining_capacity+=at;
		if debug {
			println!("derivative cost={}, remaining capacity: {}, \
			reverse capacity {}, calculated cost: {}, \
			calculated simple cost: {}", e.cost, e.remaining_capacity, er.remaining_capacity,
			getAdj(&e, &er, log_probability_cost_multiplier).1, getAdj(&e, &er, 0.0).1);
		}
		r+=getAdj(&e, &er, log_probability_cost_multiplier).1 as i64;
	}
	return r;
}


fn derivative2_at(at:i32,edges:& Vec<(MinCostEdge,MinCostEdge)>,  log_probability_cost_multiplier: f32) -> i64 {
	return relative_cost_at(at+1, edges, log_probability_cost_multiplier)-
		relative_cost_at(at, edges, log_probability_cost_multiplier);
}


// Returns a non-negative local minima on a negative cycle. Returns a number between 0 and min_capacity.
// Derivative at 0 should be negative, relative cost at 0.1 negative as well.
// Derivative at min_capacity is probably close to infinity just like negative cost.
// Local minima has negative relative cost with 0 derivative.
// Algorithm: find 0 derivative using halving. If relative cost is positive, find 0 relative cost.
// If derivative is positive, restart. If derivative is negative, go back a bit and find 0 relative cost again.

fn print_at( at: i32,edges:& Vec<(MinCostEdge,MinCostEdge)>,  log_probability_cost_multiplier:f32) {
	println!("  at {at} derivative: {}, relative cost: {}",
			derivative_at(at, edges, log_probability_cost_multiplier),
			relative_cost_at(at, edges, log_probability_cost_multiplier)) 
}

 fn find_local_minima(edges:& Vec<(MinCostEdge,MinCostEdge)>,  log_probability_cost_multiplier:f32,
	 min_capacity:i32) ->i32{
	let min_capacity0=min_capacity;
	if debug {
		println!("Find local minima called with {} edges and log_probability_cost_multiplier=\
				{log_probability_cost_multiplier}, min_capacity={min_capacity}", edges.len());
		for i in 0..edges.len() {
			println!("  fee: {}, remaining capacity: {}, edge capacity: {}, getAdj cost={}",
				edges[i].0.cost, edges[i].0.remaining_capacity,
				edges[i].0.remaining_capacity+edges[i].1.remaining_capacity,
				getAdj(&edges[i].0, &edges[i].1, log_probability_cost_multiplier).1)
		}
		print_at(0, edges, log_probability_cost_multiplier);
		print_at(1, edges, log_probability_cost_multiplier);
		print_at(5, edges, log_probability_cost_multiplier);
		print_at(min_capacity, edges, log_probability_cost_multiplier);
	}
	if derivative2_at(0, edges, log_probability_cost_multiplier) >= 0 {
		println!("Not negative cycle!!!!!!");
		return 0;
	}
	if derivative_at(min_capacity, edges, log_probability_cost_multiplier) <=0 {
		println!("Not positive at min_capacity!!!!!!");
		return 0;
	}
	let mut upper=min_capacity;
	loop {
		let mut lower=0;
		// Positive derivative, find 0 or negative derivative where upper+1 is positive.
		while upper>lower {
			let mid=(lower+upper)/2;
			if(derivative2_at(mid, edges, log_probability_cost_multiplier) <= 0) {
				lower=mid;
				if upper==lower+1 {
					upper-=1;
				}
			} else {
				upper=mid-1;
			}
		}
		if debug {
			print!(" step 1: ");
			print_at(upper, edges, log_probability_cost_multiplier);
			print_at(upper-50, edges, log_probability_cost_multiplier);
			print_at(1, edges, log_probability_cost_multiplier);
		}
		while upper < min_capacity0 &&
			 relative_cost_at(upper, edges, log_probability_cost_multiplier) >=
			 relative_cost_at(upper+1, edges, log_probability_cost_multiplier) {
				upper+=1;
		}
		if upper<=0 {
			println!("Why returning 0???");
			return 0;
		}
		if(relative_cost_at(upper, edges, log_probability_cost_multiplier) < 0) {
			return upper;
		}
		// Nonnegative relative cost with nonnegative derivative, find negative relative cost with upper+1 nonnegative.
		loop {
			lower=0;
			while(upper>lower) {
				let mid=(lower+upper)/2;
				if(relative_cost_at(mid, edges, log_probability_cost_multiplier) < 0) {
					lower=mid;
					if(upper==lower+1) {
						upper-=1;
					}
				} else {
					upper=mid-1;
				}
			}
			if(debug) {
				println!(" step 2: ");
				print_at(upper, edges, log_probability_cost_multiplier);
				print_at(upper+1, edges, log_probability_cost_multiplier);
				print_at(upper+2, edges, log_probability_cost_multiplier);
			}
			while(upper>=0 && derivative2_at(upper, edges, log_probability_cost_multiplier) == 0) {
				upper-=1;
			}
			if(upper<=0) {
				while(upper < min_capacity0 &&
					relative_cost_at(upper, edges, log_probability_cost_multiplier) >=
					relative_cost_at(upper+1, edges, log_probability_cost_multiplier)){
						upper+=1;
				}
				return upper;
			}
			if(derivative2_at(upper, edges, log_probability_cost_multiplier) > 0) {
				break;
			}
			// negative derivative while negative relative cost found.
			upper-=1;  // There should be nonnegative relative cost again.
			if(relative_cost_at(upper, edges, log_probability_cost_multiplier) < 0) {
					println!("Error: relative cost should be positive");
					return 0;
			}
		} // Total cost after optimizations: 0.137132%, p=2.91038e-09%
		// Positive derivative, start process again.
	}
}

// TODO: decrease min_capacity by finding 0 derivative???
fn decrease_total_cost( N:Vindex,adj:&mut Vec<Vec<(Vindex, i32)>>,adj2:&mut Vec<Vec<MinCostEdge>>,
	 log_probability_cost_multiplier:f32) -> bool {
	// Find negative cycle
	
	// let begin=Instant::now();
	let mut ccc=N.value;
	for i in &*adj {
		for j in i {
			ccc=crc(crc(ccc, j.0.value), j.1);
		}
	}
	// println!("adj ccc {}", ccc);
	let negative_cycle=spfa_early_terminate(N, adj, adj2);
	// elapsed("early terminate negative_cycle", begin);
	// let begin=Instant::now();
	if(debug) {
		println!("early terminate negative_cycle: {}", negative_cycle.len())
	}
	let mut min_capacity=i32::MAX;
	let mut min_cost_idxs: Vec<Vindex>=Vec::new();
	let mut edges: Vec<(MinCostEdge,MinCostEdge)>=Vec::new();

	if(debug) {println!("Possible edges:")};
	for i in 0..negative_cycle.len() {
		let u=negative_cycle[i];
		let v=negative_cycle[(i+1)%negative_cycle.len()];
		if(debug) {print!("  {u}->{v}: costs=")};
		let edges_from = &adj[u];
		let mut min_cost=i32::MAX;
		let mut min_cost_idx=Vindex::new(-1);
		for j in 0..edges_from.len() {
			if(edges_from[j].0==v) {
				if(debug) {
					let e=&adj2[u][j];
					let er=&adj2[e.v][e.reverse_idx];
					print!("{} ({}); ", edges_from[j].1, getAdj(e, er, log_probability_cost_multiplier).1)
				}
				if(edges_from[j].1 < min_cost) {
					min_cost=edges_from[j].1;
					min_cost_idx=Vindex::from_usize(j);
				}
			}
		}
		if(debug) {
			println!("");
		}
		if(min_cost_idx.value==-1) {
			println!("min_cost_idx==-1!!!!!");
			return false;
		}
		if(adj2[u].lenv()<=min_cost_idx) {
			println!("Bad index!!!!! {}, {}, {}", adj[u].len(), adj2[u].len(),  min_cost_idx);
			return false;
		}
		let e =&adj2[u][min_cost_idx];
		if(e.remaining_capacity < min_capacity) {
			min_capacity = e.remaining_capacity;
		}
		min_cost_idxs.push(min_cost_idx);
		edges.push((e.clone(), adj2[e.v][e.reverse_idx].clone()));
	}
	if(min_capacity==0 || min_cost_idxs.len()==0) {
		return false;
	}
	if(log_probability_cost_multiplier >= 0.0) {
		// if(debug) {
		// cout << "Derivative at 0: " << derivative_at(0, &edges, log_probability_cost_multiplier)
		//     << ", relative cost at 0: " << relative_cost_at(0, &edges, log_probability_cost_multiplier)
		//     << ", relative cost at 1: " << relative_cost_at(1, &edges, log_probability_cost_multiplier)
		//     << ", derivative at " << min_capacity << ": " 
		//     << derivative_at(min_capacity, &edges, log_probability_cost_multiplier)
		//     << endl;}
		min_capacity=find_local_minima(&edges, log_probability_cost_multiplier, min_capacity);
		// min_capacity=(relative_cost_at(floor(fmin_capacity), edges, log_probability_cost_multiplier) <
						// relative_cost_at(floor(fmin_capacity)+1, edges, log_probability_cost_multiplier))
						// ? floor(fmin_capacity) : (floor(fmin_capacity)+1);
		// if(debug) {
		//  cout << "Find local minima returned " << min_capacity << 
		//     ", derivative at 0: " << derivative_at(0, &edges, log_probability_cost_multiplier)
		//     << ", derivative at new min capacity(" << min_capacity << "): " 
		//     << derivative_at(min_capacity, &edges, log_probability_cost_multiplier)
		//     << ", relative cost at min_capacity: " <<
		//     relative_cost_at(min_capacity, &edges, log_probability_cost_multiplier)
		//     << endl;}
	}
	if(min_capacity==0 || min_cost_idxs.len()==0) {
		return false;
	}
	if(debug) {println!("min capacity={}", min_capacity);}
	// decrease using min capacity
	
	// if(debug){cout << "adjusted cost before modification: " << adj_total_cost(N, adj2) << "+" <<
	//     adj_total_mlog_prob(N, adj2) << "*" << log_probability_cost_multiplier << "=" <<
	//     adj_total_cost(N, adj2)+adj_total_mlog_prob(N, adj2)*log_probability_cost_multiplier
	//      << endl;}
	for i in 0..min_cost_idxs.len() {
		let u=negative_cycle[i];
		if(adj2[u].lenv()<=min_cost_idxs[i]) {
			println!("Bad index2!!!!!");
			return false;
		}
		let e = &adj2[u][min_cost_idxs[i]];
		let v=e.v;
		let reverse_idx=e.reverse_idx;
		if(e.remaining_capacity < min_capacity) {
			println!("too small capacity {} {}", min_capacity, e.remaining_capacity);
			return false;
		}
		if(adj2[v].lenv()<=e.reverse_idx) {
			println!("Bad index3!!!!!");
			return false;
		}
		adj2[u][min_cost_idxs[i]].remaining_capacity-=min_capacity;
		adj2[v][reverse_idx].remaining_capacity+=min_capacity;
		let e = &adj2[u][min_cost_idxs[i]];
		let er=&adj2[v][e.reverse_idx];
		adj[u][min_cost_idxs[i]]=getAdj(&e, &er, log_probability_cost_multiplier);
		adj[v][e.reverse_idx]=getAdj(&er, &e, log_probability_cost_multiplier);
	}
	// if(debug){ cout << "adjusted cost after modification: "  << adj_total_cost(N, adj2) << "+" <<
	//     adj_total_mlog_prob(N, adj2) << "*" << log_probability_cost_multiplier << "=" <<
	//     adj_total_cost(N, adj2)+adj_total_mlog_prob(N, adj2)*log_probability_cost_multiplier
	//      << endl;}
	// elapsed("decreased total cost rest", begin);

	return true;
}

// Sets flow values to min cost flow.
pub fn min_cost_flow(n: usize, s: usize, t: usize, value: i32, log_probability_cost_multiplier: i32,
	lightning_data: &mut Vec<OriginalEdge>, cost_scaling: i32) {
		let nv=Vindex::from_usize(n);
		let sv=Vindex::from_usize(s);
		let tv=Vindex::from_usize(t);
	   let scaled_log_probability_cost_multiplier=log_probability_cost_multiplier*cost_scaling;
	// let mut ccc=0;
	for l in &mut *lightning_data {
		// ccc= crc(crc(crc(crc(crc(crc(ccc, l.u.value), l.v.value), l.capacity), l.cost), l.flow), l.guaranteed_liquidity);
		l.cost*=cost_scaling;
		if(l.cost==0) {
			l.cost=1;
		}
	}
	// println!("lightning_data after read crc {}", ccc);

	let M=lightning_data.len();
	// Find max path
	let begin = Instant::now();
	let mut g=MaxFlowGraph::new(nv);
	let mut edges_with_flow:Vec<Vindex>=Vec::new();
	for i in 0..M {
		let data=&lightning_data[i];
		edges_with_flow.push(g.addEdge(Vindex::from_usize(data.u), Vindex::from_usize(data.v), data.capacity));
	}

	println!("Maximum flow {}", g.DinicMaxflow(sv, tv, value));
	elapsed("max flow", begin);
	let begin = Instant::now();
	for i in 0..M {
		let u=lightning_data[i].u;
		let flow = g.adj[u][edges_with_flow[i]].flow;
		lightning_data[i].flow=flow;
	}
	elapsed("edges_with_flow flow info", begin);

	println!("Total cost before optimizations: {}", total_cost(lightning_data));
	let mut rounds=0;

	let begin=Instant::now();
	let mut adj:Vec<Vec<(Vindex,i32)>>=Vec::new(); // v, cost
	let mut adj2: Vec<Vec<MinCostEdge>>=Vec::new(); // flow, capacity  // same for negative for now
	for _ in 0..n {
		adj.push(Vec::new());
		adj2.push(Vec::new());
	}
	let mut numneg=0;
	let mut lightning_data_idx:Vec<Vindex>=Vec::new();
	for i in 0..lightning_data.len() 
	{
		let data  = &lightning_data[i];
		let u=data.u;
		let v=data.v;
		let e:MinCostEdge =MinCostEdge {v:Vindex::from_usize(data.v), remaining_capacity: data.capacity-data.flow, cost: data.cost,
			 reverse_idx: adj2[data.v].lenv(), guaranteed_liquidity:data.guaranteed_liquidity};
		let er=MinCostEdge {v:Vindex::from_usize(data.u), remaining_capacity:data.flow, cost: -data.cost,  reverse_idx: adj2[data.u].lenv(),
				guaranteed_liquidity: data.guaranteed_liquidity};
		if(er.remaining_capacity > 0) {
			numneg+=1;
		}
		lightning_data_idx.push(adj2[data.u].lenv());
		adj[data.u].push(getAdj(&e, &er, scaled_log_probability_cost_multiplier as f32));
		adj[data.v].push(getAdj(&er, &e, scaled_log_probability_cost_multiplier as f32));
		adj2[u].push(e);
		adj2[v].push(er);
	}
	let mut ccc=0;
	for i in &*adj {
		for j in i {
			ccc=crc(crc(ccc, j.0.value), j.1);
		}
	}
	println!("adj0 ccc {}", ccc);
	let mut ccc=0;
	for i in &*adj2 {
		for j in i {
			ccc=crc(crc(ccc, j.remaining_capacity), j.reverse_idx.value);
		}
	}
	println!("adj20 ccc {}", ccc);
	// return;
	// if(debug) {
	//     cout << "numneg: " << numneg <<endl;
	//     cout << "adj_total_cost: " << adj_total_cost(N, adj2)/value*100.0 << "%" << endl;
	// }
	elapsed("setup early terminate", begin);
	let cost_after_0=adj_total_cost(nv, &adj2)/1000000;
	let mut cost_after_100:i64=0;
	let mut cost_after_200:i64=0;
	let mut cost_after_400:i64=0;
	let mut p_after_100=0.0;
	let mut p_after_200=0.0;
	let mut p_after_400=0.0;
	while(decrease_total_cost(nv, &mut adj, &mut adj2, scaled_log_probability_cost_multiplier as f32)) {
		let distance:Duration=begin.elapsed();
		if(cost_after_100==0 && distance.as_millis()>100) {
			cost_after_100=adj_total_cost(nv, &adj2)/1000000;
			p_after_100=(-adj_total_mlog_prob(nv, &adj2)).exp2();
		}
		if(cost_after_200==0 && distance.as_millis()>200) {
			cost_after_200=adj_total_cost(nv, &adj2)/1000000;
			p_after_200=(-adj_total_mlog_prob(nv, &adj2)).exp2();

		}
		if(cost_after_400==0 && distance.as_millis()>400) {
			cost_after_400=adj_total_cost(nv, &adj2)/1000000;
			p_after_400=(-adj_total_mlog_prob(nv, &adj2)).exp2();
		}
		// if(debug) {
		//     cout << "total cost " << adj_total_cost(N, adj2)/1000000.0/value*100.0 << "%" << endl;
		// }
		rounds+=1;
		if(distance.as_millis()>2000) {
			println!("Breaking after 2s");
			break;
		}
	}
	println!("Total cost after optimizations: {}%, p={}%",
		adj_total_cost(nv, &adj2) as f32/cost_scaling as f32/1000000.0/value as f32*100.0,
		(-adj_total_mlog_prob(nv, &adj2)).exp2()*100.0);
	println!("cost after 0 rounds: {}%", (cost_after_0/cost_scaling as i64) as f32*1.0/value as f32*100.0);  // 0.1404%)
	println!("cost after 100: {}%, p={}%", (cost_after_100/cost_scaling as i64) as f32/value as f32*100.0, p_after_100*100.0);
	println!("cost after 200: {}%, p={}%", (cost_after_200/cost_scaling as i64) as f32/value as f32*100.0, p_after_200*100.0);
	println!("cost after 400: {}%, p={}%", (cost_after_400/cost_scaling as i64) as f32/value as f32*100.0, p_after_400*100.0);
	elapsed("total time", begin);  // 2500ms for 0.5 BTC
	println!("{} rounds, satoshis={}", rounds, value);
	println!("{} rounds", rounds);
	for i in 0..lightning_data.len() {
		let data =&lightning_data[i];
		let u=data.u;
		let e=&adj2[u][lightning_data_idx[i]];
		let er=&adj2[e.v][e.reverse_idx];
		lightning_data[i].flow=er.remaining_capacity;
	}
}
