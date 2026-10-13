"""Conserved gross budgets and NUMA-balanced directory placement."""
GIB=1024**3
MIB=1024**2
COUNTS=(1,2,4,24)

def placement(slot,domains,rotation=0):
    if domains not in COUNTS or not 0<=slot<24 or rotation<0:
        raise ValueError('invalid placement')
    # Both 12-slot NUMA sets span every small group;24-way remains bijective.
    perm=slot if slot<12 else 12+(slot-12+5)%12
    return (perm+rotation)%domains

def layout(domains,total_bytes=18*GIB,total_inodes=24*32768,total_journal_mib=384):
    if domains not in COUNTS or any(v%domains for v in (total_bytes,total_inodes,total_journal_mib)):
        raise ValueError('nonintegral budget')
    if total_bytes//domains<128*MIB or total_journal_mib//domains<16:
        raise ValueError('filesystem too small')
    return [dict(index=i,bytes=total_bytes//domains,inodes=total_inodes//domains,
        journal_mib=total_journal_mib//domains,block_size=4096,inode_size=256,
        reserved_percent=0) for i in range(domains)]

def required_free(total_bytes,slots=24):
    if not 1<=slots<=24 or total_bytes<=0:raise ValueError('budget')
    return total_bytes+slots*130*MIB+512*MIB+6*GIB

def matrix_rotation(block):
    if not 0<=block<5:raise ValueError('block')
    return (0,5,10,15,20)[block]
