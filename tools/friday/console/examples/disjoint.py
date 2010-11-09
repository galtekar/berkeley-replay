
def bfs(C, F, source, sink):
	P = [-1] * len(C) # parent in search tree
	P[source] = source
	queue = [source]
	while queue:
		u = queue.pop(0)
		for v in xrange(len(C)):
			if C[u][v] - F[u][v] > 0 and P[v] == -1:
				P[v] = u
				queue.append(v)
				if v == sink:
					path = []
			
					while True:
						path.insert(0, v)
						if v == source:
							break
						v = P[v]

					return path

	return None

# Returns Max-flow flow matrix.
def edmonds_karp(C, source, sink):
	n = len(C) # C is the capacity matrix
	F = [[0] * n for _ in xrange(n)]
	# residual capacity from u to v is C[u][v] - F[u][v]

	while True:
		path = bfs(C, F, source, sink)
		if not path:
			break
		flow = 10000000 # Inf
		# traverse path to find smallest capacity
		for i in xrange(len(path) - 1):
			u,v = path[i], path[i+1]
			flow = min(flow, C[u][v] - F[u][v])

		# traverse path to update flow
		for i in range(len(path) - 1):
			u,v = path[i], path[i+1]
			F[u][v] += flow
			F[v][u] -= flow

	return F

def find_all_paths(graph, start, end, path=[]):
	path = path + [start]
	if start == end:
		return [path]

	paths = []
	for node in xrange(len(graph[start])):
		if graph[start][node] > 0 and (node not in path):

			newpaths = find_all_paths(graph, node, end, path)
			for newpath in newpaths:
				paths.append(newpath)

	return paths

def find_path(graph, start, end, path=[]):
	path = path + [start]

	if start == end:
		return path
	
	for neighbor in xrange(len(graph[start])):
		if graph[start][neighbor] > 0 and (neighbor not in path):

			newpath = find_path(graph, neighbor, end, path)
			if newpath: 
				return newpath

	return None

def edge_disjoint_paths_old(C, source, sink):
	n = len(C) # C is the capacity matrix
	F = edmonds_karp(C, source, sink)

	assert(source != sink)

	disjoint_paths = []
	edge_set = set([])

	all_paths = find_all_paths(F, source, sink)

	for path in all_paths:
		duplicate_edge = False

#print "Path = ", path

		path_edge_set = set([])
		for i in xrange(len(path)-1):
			path_edge_set.add((path[i], path[i+1]))
			

#		print len(edge_set & path_edge_set)
		if len(edge_set & path_edge_set) == 0:
			disjoint_paths.append(path)
			edge_set = edge_set | path_edge_set

#print edge_set, path_edge_set

	return disjoint_paths

def edge_disjoint_paths(C, source, sink):
	n = len(C) # C is the capacity matrix
	F = edmonds_karp(C, source, sink)

	disjoint_paths = []
	edge_set = set([])

	# Keep finding paths and removing them until
	# we run out of paths.
	while True:
		path = find_path(F, source, sink)

		if source == sink:
			return []

		# Remove the path from the graph.
		if path:
			for i in range(len(path)-1):
				F[path[i]][path[i+1]] -= 1

			disjoint_paths.append(path)
		else:
			break
	
	return disjoint_paths


def vertex_disjoint_paths_old(C, source, sink):

	F = edmonds_karp(C, source, sink)

	paths = []

	while True:
		path = find_path(F, source, sink)
		
		if source == sink:
			return []

		print path
		if path:
			for i in range(len(path)-1)[1:len(path)-1]:
				for j in xrange(len(F)):
#print j, i, path[i]
					F[j][path[i]] = 0

			paths.append(path)
		else:
			break

	return paths

def vertex_disjoint_paths(C, source, sink):

	D = vertex_to_edge(C)

	disjoint_paths = edge_disjoint_paths(D, source*2+1, sink*2)

	assert(len(disjoint_paths) <= max_flow(D, source*2+1, sink*2))

	return disjoint_paths
		
def max_flow(C, source, sink):
	n = len(C) # C is the capacity matrix
	F = edmonds_karp(C, source, sink)

	return sum([F[source][i] for i in xrange(n)])

# Produces an MxN bitmap adjacency matrix that is initialized
# with the specified paths.
def path_matrix(m, n, paths):
	# Matrices must be rank 2 with at least one row and column
	assert(m > 0 and n > 0)

	result = []
	for i in range(m):
		result.append([0]*n)

	for path in paths:
		for i in xrange(len(path)-1):
			result[path[i]][path[i+1]] = 1

	return result

def zero_matrix(m, n):
	# Matrices must be rank 2 with at least one row and column
	assert(m > 0 and n > 0)

	result = []
	for i in range(m):
		result.append([0]*n)

	return result

def list_matrix(m, n):
	# Matrices must be rank 2 with at least one row and column
	assert(m > 0 and n > 0)

	result = []
	for i in range(m):
		result.append([[]]*n)

	return result

# Transform all vertices in the input matrix into an edge.
def vertex_to_edge(M):
	m = len(M)
	Z = zero_matrix(m*2, m*2)

	for i in range(m):
		# Connect incoming and outgoing nodes.
		Z[i*2][i*2+1] = 1
#print i*2, "-->", i*2+1
		Z[i*2+1][i*2] = 1
#print i*2+1, "-->", i*2

		for j in range(m):
			if i != j:
				# Connect to all neighbors.
				Z[i*2+1][j*2] = M[i][j]
#print i*2+1, "(%d)"%(i), "-->", j*2, "(%d)"%(j), "=", M[i][j]
	
	return Z


def test():
	source = 1
	sink = 9

	M = path_matrix(10, 10, [[0, 1, 2, 3], [0, 7, 2, 1], [0, 4, 5, 3], [0, 7, 4, 3],
		[2, 0, 9, 5, 3, 7]])
	M = [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0], [1, 0, 1, 0, 1, 1, 1, 1, 0, 0], [0, 0, 0, 1, 0, 1, 0, 0, 0, 0], [0, 0, 1, 0, 1, 0, 0, 1, 0, 1], [1, 1, 0, 1, 0, 0, 0, 0, 0, 1], [1, 1, 1, 0, 0, 0, 1, 0, 0, 1], [0, 1, 0, 0, 0, 1, 0, 1, 1, 0], [1, 0, 0, 0, 0, 0, 0, 0, 0, 0], [1, 0, 1, 0, 0, 0, 1, 1, 0, 1], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]]
	print find_all_paths(M, source, sink) 
	print edge_disjoint_paths(M, source, sink)
	print vertex_disjoint_paths(M, source, sink)
	print max_flow(M, source, sink)

test()
