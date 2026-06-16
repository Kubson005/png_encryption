# Wymagania projektowe

- Napisać program do szyfrowania i deszyfracji pliku multimedialnego algorytmem RSA.

- Zaszyfrować wyłącznie masę bitową pliku, pozostawiając nagłówek i metadane bez zmian — plik
  zaszyfrowany musi się dać otworzyć standardowymi aplikacjami, ale jego zawartość powinna być
  zakodowana (zaszyfrowana). W razie konieczności modyfikacji metadanych, proszę uzasadnić dokonany wybór.

  > **Uwaga!** Dla niektórych formatów plików identyfikacja, które fragmenty są danymi, a które metadanymi,
  > może być trudna. W razie wątpliwości, proszę pytać.

- Dla plików wykorzystujących kompresję, należy przetestować (o ile to możliwe):
  - szyfrowanie zdekompresowanych danych, a następnie skompresowanie tak utworzonego szyfrogramu;
  - bezpośrednie szyfrowanie skompresowanych danych.

  Czy obie metody są równoważne?

- Metodę szyfrującą i deszyfrującą należy napisać samodzielnie, bez użycia bibliotek szyfrujących.
  Można skorzystać z gotowych bibliotek do:
  - obliczeń na dużych liczbach (w tym przeprowadzania operacji potęgi modulo);
  - generowania liczb pierwszych;
  - generowania liczb losowych.

- Operację szyfrowania przeprowadzić wykorzystując **Electronic Code Book** oraz co najmniej jedną
  inną metodę.

- Ocenić, czy informacje są możliwe do odczytania po zaszyfrowaniu (np. czy widać zarys obiektu
  dla ECB).

- Skorzystać z gotowej funkcji szyfrującej metodą RSA. Szyfrować tą samą parą kluczy. Porównać
  wynik szyfrowania z rezultatami implementowanych algorytmów.

- Podjąć próbę wyjaśnienia przyczyny ewentualnych wyraźnych różnic.
