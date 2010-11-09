# Returns a list of all paths (i.e., list of sets) from start to end.
def find_all_paths(graph, start, curr, end, path=set()):
	# Add the current node to the path.
	if start != curr and end != curr:
		path.add(curr)

	if curr == end:
		return [path]
	# start doesn't have any neighbors, and thus no path to end
	if not graph.has_key(curr):
		return []

	paths = []
	for node in graph[curr]:
		# Avoid cycles. 
		if node not in path:
			newpaths = find_all_paths(graph, start, node, end, path.copy())
			for newpath in newpaths:
				paths.append(newpath)
	return paths

def is_disjoint(pathlist):
	for path1 in pathlist:
		for path2 in pathlist:
			if path1 != path2:
				if len(path1 & path2) > 0:
					return False
	return True

# Returns True iff some k-subset of paths in pathlist is disjoint.
def has_k_disjoint_paths(pathlist, k, k_subset=[]):
	if k == 0:
		if is_disjoint(k_subset):
			return True
		else:
			return False

	for path in pathlist:
		# Avoid duplicates.
		if path not in k_subset:
			ret = has_k_disjoint_paths(pathlist, k-1, k_subset + [path])

			if ret == True:
				return True

	return False
#
#graph = {'A': ['B', 'C'],
#	'B': ['C', 'D'],
#	'C': ['D'],
#	'D': ['C'],
#	'E': ['F'],
#	'F': ['C']}

#allpaths = find_all_paths(graph, 'A', 'A', 'C')

#print allpaths

#print has_k_disjoint_paths(allpaths, 2)
