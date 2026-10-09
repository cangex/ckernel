from pathlib import Path
import run_matrix as runner

runner.B=Path('/home/ckernel-whitebox-w2-build-r1')
runner.D=runner.W/'matrix-go-r6'
if __name__=='__main__':runner.main()
