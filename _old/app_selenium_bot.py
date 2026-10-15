import time
import random
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

# --- CONFIGURATION ---
FORM_URL = "https://forms.gle/EmnWfAewViStv3Z99"
ITERATIONS = 65


# ---------------------

def fill_form():
    chrome_options = Options()
    # If you want it to run in the background, uncomment the line below:
    # chrome_options.add_argument("--headless")

    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)

    try:
        for i in range(ITERATIONS):
            print(f"Starting submission {i + 1}/{ITERATIONS}...")
            driver.get(FORM_URL)
            time.sleep(2)  # Wait for page to load

            # 1. Handle Radio Buttons (Multiple Choice)
            radio_groups = driver.find_elements(By.XPATH, '//div[@role="radiogroup"]')
            for group in radio_groups:
                options = group.find_elements(By.XPATH, './/div[@role="radio"]')
                if options:
                    random.choice(options).click()
                    time.sleep(0.4)

            # 2. Handle Checkboxes (Tick boxes)
            # This finds all checkbox containers
            checkbox_containers = driver.find_elements(By.XPATH, '//div[contains(@aria-describedby, "i")]')
            for container in checkbox_containers:
                checkboxes = container.find_elements(By.XPATH, './/div[@role="checkbox"]')
                if checkboxes:
                    # Selects 1 or 2 random boxes
                    to_select = random.sample(checkboxes, k=random.randint(1, min(2, len(checkboxes))))
                    for box in to_select:
                        box.click()
                        time.sleep(0.3)

            # 3. Handle Dropdowns
            dropdowns = driver.find_elements(By.XPATH, '//div[@role="listbox"]')
            for dd in dropdowns:
                dd.click()  # Click to open
                time.sleep(0.8)
                options = driver.find_elements(By.XPATH, '//div[@role="option" and @tabindex="0"]')
                if options:
                    random.choice(options).click()  # Select random
                time.sleep(0.4)

            # 4. Submit the form
            try:
                # Look for the button that is styled as a "Submit" button
                submit_button = driver.find_element(By.XPATH,
                                                    '//div[@role="button"]//span[text()="Submit" or text()="Enviar" or text()="Submit"]')
                submit_button.click()
            except:
                # Fallback: find the first primary action button
                btns = driver.find_elements(By.XPATH, '//div[@role="button"]')
                btns[-1].click()  # Usually the last button on the page is 'Submit'

            print(f"Done: {i + 1}/{65}")
            time.sleep(1.5)  # Wait before starting the next form

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        driver.quit()


if __name__ == "__main__":
    fill_form()