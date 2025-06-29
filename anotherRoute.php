Route::middleware('auth')->get('/dashboard', function () {
    return view('dashboard');
})->name('dashboard');
