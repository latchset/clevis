lsof = find_program('lsof', required: false)
pgrep = find_program('pgrep', required: false)

if lsof.found() and pgrep.found()
  test('sss-child-process-cleanup', find_program('sss-child-process-cleanup'), env: env, timeout: 30)
else
  warning('Will not run sss-child-process-cleanup test due to missing dependencies (lsof, pgrep)!')
endif
