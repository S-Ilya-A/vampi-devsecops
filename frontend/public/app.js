/* VAmPI Library web client. Talks to the API through the /api/ proxy in nginx. */

var API = '/api';

function token() {
  return localStorage.getItem('vampi_token');
}

function authHeaders() {
  return token() ? { Authorization: 'Bearer ' + token() } : {};
}

function showMessage(html) {
  document.getElementById('message').innerHTML = html;
}

function formData(form) {
  var out = {};
  $(form).serializeArray().forEach(function (f) { out[f.name] = f.value; });
  return out;
}

function postJSON(path, body) {
  return $.ajax({
    url: API + path,
    method: 'POST',
    contentType: 'application/json',
    data: JSON.stringify(body),
    headers: authHeaders()
  });
}

function loadBooks() {
  $.getJSON(API + '/books/v1').done(function (data) {
    var html = '';
    data.Books.forEach(function (b) {
      html += '<li><a href="#' + b.book_title + '">' + b.book_title + '</a> by ' + b.user + '</li>';
    });
    document.getElementById('books').innerHTML = html;
  });
}

function openBook(title) {
  $.ajax({ url: API + '/books/v1/' + title, headers: authHeaders() })
    .done(function (b) {
      $('#book-detail').html(
        '<h3>' + b.book_title + '</h3><p>Owner: ' + b.owner + '</p><pre>' + b.secret + '</pre>'
      );
    })
    .fail(function () {
      $('#book-detail').html('Could not open <b>' + title + '</b>');
    });
}

function refreshSession() {
  if (!token()) {
    $('#auth').prop('hidden', false);
    $('#library').prop('hidden', true);
    $('#whoami').text('');
    return;
  }
  $.ajax({ url: API + '/me', headers: authHeaders() })
    .done(function (me) {
      $('#whoami').html('Signed in as ' + me.data.username + (me.data.admin ? ' (admin)' : ''));
      $('#auth').prop('hidden', true);
      $('#library').prop('hidden', false);
      loadBooks();
    })
    .fail(function () {
      localStorage.removeItem('vampi_token');
      refreshSession();
    });
}

$(function () {
  $('#session-start').text(moment().format('LLL'));

  $('#login-form').on('submit', function (ev) {
    ev.preventDefault();
    postJSON('/users/v1/login', formData(this)).done(function (r) {
      if (r.auth_token) {
        localStorage.setItem('vampi_token', r.auth_token);
        showMessage('');
        refreshSession();
      } else {
        showMessage(r.message);
      }
    });
  });

  $('#register-form').on('submit', function (ev) {
    ev.preventDefault();
    postJSON('/users/v1/register', formData(this)).done(function (r) {
      showMessage(r.message);
    });
  });

  $('#book-form').on('submit', function (ev) {
    ev.preventDefault();
    postJSON('/books/v1', formData(this)).done(function (r) {
      showMessage(r.message);
      loadBooks();
    });
  });

  $('#lookup-form').on('submit', function (ev) {
    ev.preventDefault();
    window.location.hash = formData(this).book_title;
  });

  $('#logout').on('click', function () {
    localStorage.removeItem('vampi_token');
    refreshSession();
  });

  // deep links: /#<book title>
  $(window).on('hashchange', function () {
    openBook(decodeURIComponent(window.location.hash.slice(1)));
  });
  if (window.location.hash) {
    openBook(decodeURIComponent(window.location.hash.slice(1)));
  }

  // UI preferences can be pushed from the partner portal that embeds this page
  window.addEventListener('message', function (ev) {
    var prefs = _.merge({}, JSON.parse(ev.data));
    if (prefs.banner) {
      showMessage(prefs.banner);
    }
  });

  refreshSession();
});
