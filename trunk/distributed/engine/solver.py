# vim:ts=4:sw=4:expandtab
#
import re,subprocess,misc,select

_pat_stp_assign = re.compile('ASSERT\(\s*(?P<var>[\w\d]+)\s*=\s*(?P<val>0(b|x)[\w\d]+)\s*\);')


def _extract_assignment( assign_str ):
    assign_map = {}
    for m in _pat_stp_assign.finditer(assign_str):
        val = int(m.group("val"), 0)
        assign_map[m.group("var")] = val
    return assign_map

class SolverException(Exception):
    pass

def solve_formula( formula_str ):
    assert( len(formula_str) )

    cmd = ["/usr/bin/stp", "-p"]
#    p = subprocess.Popen(cmd_str, stdout=subprocess.PIPE, \
#            stdin=subprocess.PIPE, stderr=subprocess.PIPE, \
#            shell=True)
    p = misc.start_child(cmd)
    print "len formula:", len(formula_str)
    p.stdin.writelines(formula_str+"QUERY(FALSE);")
    p.stdin.close()

    res_list = []
    while True:
        sock_list = [ p.stdout ]
        #print 'here1'
        ready_socks = select.select( sock_list, [], sock_list )
        #print 'here2'
        if p.stdout in ready_socks[0]:
            res = p.stdout.read()
            if res:
                res_list.append(res)
            else:
                break

            #print 'here3'
        if p.stdout in ready_socks[2]:
            break

    p.kill()
    p.wait()
#    except KeyboardInterrupt:
#        p.kill()
#        p.wait()
#        raise

    out_str = ''.join(res_list)
    #misc.debug( "solver result:", out_str )
    assign_map = _extract_assignment( out_str )
    if len(assign_map) == 0:
        raise SolverException("No solution")
    else:
        return assign_map
