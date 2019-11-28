function success(res, data) {
  reply(res, 'success', data)
}

function fail(res, data) {
  reply(res, 'fail', data)
}

function error(res, data) {
  reply(res, 'error', data)
}

function reply(res, status, data) {
  res.json({
    status: status,
    data: data
  })
}

module.exports = {
  success, fail, error
}