from pathlib import Path
import sys
import run_matrix as runner

runner.B=Path('/home/ckernel-whitebox-w3-build-r1')
runner.D=runner.W/('matrix-r5' if sys.argv[1]=='core' else 'matrix-go-r6')
if __name__=='__main__':runner.main()
